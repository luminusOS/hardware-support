import hashlib
import importlib.util
import io
import json
import os
import signal
import sys
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

ENTRY = Path(__file__).resolve().parents[1] / "bin/pack-local-candidate.py"
NAMES = (
    "candidate.json",
    "nvidia.ko",
    "nvidia-drm.ko",
    "nvidia-modeset.ko",
    "nvidia-uvm.ko",
    "nvidia-runtime-620.70.06.tar.gz",
    "nvidia-firmware-ga10x-620.70.06.tar.gz",
    "source-and-notices.tar.gz",
)
SPEC = importlib.util.spec_from_file_location("pack_local_candidate", ENTRY)
assert SPEC is not None and SPEC.loader is not None
packer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packer)


class PackLocalCandidateTests(unittest.TestCase):
    def make_candidate(self, root):
        candidate = root / "candidate"
        candidate.mkdir(mode=0o700)
        claims = {}
        for name in NAMES[1:]:
            content = ("bytes:" + name).encode()
            (candidate / name).write_bytes(content)
            claims[name] = {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        (candidate / "candidate.json").write_text(json.dumps(
            {"schema": 1, "producer": {}, "target": {}, "files": claims},
            sort_keys=True, separators=(",", ":"),
        ) + "\n")
        return candidate

    def test_writes_repeatable_ustar_and_reports_hashes_of_packed_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = self.make_candidate(root)
            first = root / "first.tar"
            second = root / "second.tar"
            result = packer.pack(candidate, first)
            repeated = packer.pack(candidate, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(result, repeated)
            raw = first.read_bytes()
            self.assertEqual(result["archive_size"], len(raw))
            self.assertEqual(result["archive_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(result["manifest_sha256"],
                             hashlib.sha256((candidate / "candidate.json").read_bytes()).hexdigest())
            self.assertLessEqual(len(raw), packer.ARCHIVE_LIMIT)
            self.assertEqual(first.stat().st_mode & 0o777, 0o600)
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                self.assertEqual(archive.getnames(), list(NAMES))
                for member, name in zip(archive.getmembers(), NAMES):
                    self.assertEqual((member.mode, member.uid, member.gid, member.mtime),
                                     (0o600, 0, 0, 0))
                    self.assertEqual((member.uname, member.gname, member.pax_headers), ("", "", {}))
                    if name != "candidate.json":
                        self.assertEqual(archive.extractfile(member).read(),
                                         ("bytes:" + name).encode())

    def test_rejects_unexpected_entry_and_symlink_without_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = self.make_candidate(root)
            output = root / "out.tar"
            (candidate / "extra").write_bytes(b"x")
            with self.assertRaises(ValueError):
                packer.pack(candidate, output)
            self.assertFalse(output.exists())
            (candidate / "extra").unlink()
            (candidate / NAMES[1]).unlink()
            (candidate / NAMES[1]).symlink_to(candidate / NAMES[2])
            with self.assertRaises(ValueError):
                packer.pack(candidate, output)
            self.assertFalse(output.exists())

    def test_rejects_manifest_digest_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = self.make_candidate(root)
            (candidate / NAMES[1]).write_bytes(b"changed")
            with self.assertRaises(ValueError):
                packer.pack(candidate, root / "out.tar")
            self.assertFalse((root / "out.tar").exists())

    def test_rejects_same_size_digest_tamper(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = self.make_candidate(root)
            path = candidate / NAMES[1]
            path.write_bytes(b"x" * path.stat().st_size)
            with self.assertRaises(ValueError):
                packer.pack(candidate, root / "out.tar")
            self.assertFalse((root / "out.tar").exists())

    def test_output_requires_owned_private_real_parent_and_simple_basename(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = self.make_candidate(root)
            open_parent = root / "open"
            open_parent.mkdir(mode=0o755)
            link_parent = root / "linked"
            link_parent.symlink_to(root, target_is_directory=True)
            for output in (open_parent / "out.tar", link_parent / "out.tar",
                           "", str(root) + "/out.tar/", str(root) + "/.", str(root) + "/.."):
                with self.subTest(output=output), self.assertRaises((ValueError, OSError)):
                    packer.pack(candidate, output)

    def test_collision_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = self.make_candidate(root)
            output = root / "out.tar"
            output.write_bytes(b"keep")
            with self.assertRaises((ValueError, FileExistsError)):
                packer.pack(candidate, output)
            self.assertEqual(output.read_bytes(), b"keep")

    def test_rejects_output_in_candidate_directory_without_touching_input(self) -> None:
        for output_name in ("out.tar", "../candidate/out.tar", "candidate.json"):
            with self.subTest(output_name=output_name), tempfile.TemporaryDirectory() as temp:
                candidate = self.make_candidate(Path(temp))
                trusted = {entry.name: entry.read_bytes() for entry in candidate.iterdir()}
                with self.assertRaisesRegex(ValueError, "output parent must differ from candidate"):
                    packer.pack(candidate, candidate / output_name)
                self.assertEqual(
                    {entry.name: entry.read_bytes() for entry in candidate.iterdir()},
                    trusted,
                )

    def test_signal_at_rollback_entry_preserves_failure_and_removes_archive(self) -> None:
        self.assert_signal_at_boundary("rollback")

    def test_signal_before_commit_removes_archive(self) -> None:
        self.assert_signal_at_boundary("before_commit")

    def test_signal_after_commit_still_reports_archive(self) -> None:
        self.assert_signal_at_boundary("after_commit")

    def assert_signal_at_boundary(self, boundary: str) -> None:
        handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        for sig, handler in handlers.items():
            self.addCleanup(signal.signal, sig, handler)
        lines = ENTRY.read_text().splitlines()
        if boundary == "before_commit":
            inject_line = next(i + 1 for i, line in enumerate(lines)
                               if line.startswith("        complete = "))
        else:
            inject_line = max(i + 2 for i, line in enumerate(lines) if line == "    finally:")
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signum=signum), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                candidate = self.make_candidate(root)
                output = root / "out.tar"
                descriptors = []
                stdout = io.StringIO()
                stderr = io.StringIO()

                def trace(frame, event, arg, descriptors=descriptors, signum=signum):
                    if frame.f_code is not packer.pack.__code__:
                        return None
                    if event == "line" and frame.f_lineno == inject_line and not descriptors:
                        descriptors.extend(frame.f_locals[name]
                                           for name in ("candidate_fd", "parent_fd", "output_fd"))
                        signal.raise_signal(signum)
                    return trace

                with (
                    patch.object(sys, "argv", ["packer", "--candidate", str(candidate),
                                               "--output", str(output)]),
                    patch.object(packer, "ARCHIVE_LIMIT", 512 if boundary == "rollback"
                                 else packer.ARCHIVE_LIMIT),
                    redirect_stdout(stdout),
                    redirect_stderr(stderr),
                ):
                    previous_trace = sys.gettrace()
                    sys.settrace(trace)
                    try:
                        if boundary == "after_commit":
                            packer.main()
                        else:
                            with self.assertRaises(SystemExit) as failure:
                                packer.main()
                            expected_code = 2 if boundary == "rollback" else 128 + signum
                            self.assertEqual(failure.exception.code, expected_code)
                    except KeyboardInterrupt:
                        self.fail("SIGINT escaped outside a cancellation checkpoint")
                    finally:
                        sys.settrace(previous_trace)
                        self.assertEqual(len(descriptors), 3)
                        leaked = []
                        for fd in descriptors:
                            try:
                                os.fstat(fd)
                            except OSError:
                                continue
                            os.close(fd)
                            leaked.append(fd)
                        self.assertEqual(leaked, [])
                self.assertEqual({sig: signal.getsignal(sig) for sig in handlers}, handlers)
                if boundary == "after_commit":
                    self.assertEqual(json.loads(stdout.getvalue())["archive_sha256"],
                                     hashlib.sha256(output.read_bytes()).hexdigest())
                else:
                    self.assertFalse(output.exists())
                    self.assertEqual(stdout.getvalue(), "")
                if boundary == "rollback":
                    self.assertIn("archive exceeds", stderr.getvalue())
                else:
                    self.assertEqual(stderr.getvalue(), "")

    def test_rollback_defers_interrupt_until_archive_is_removed_and_closed(self) -> None:
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signum=signum):
                self.assert_rollback_defers_interrupt(signum)

    def assert_rollback_defers_interrupt(
        self, signum: signal.Signals,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = self.make_candidate(root)
            output = root / "out.tar"
            trusted = {entry.name: entry.read_bytes() for entry in candidate.iterdir()}
            real_unlink = os.unlink
            interrupted_fds: list[int] = []

            def interrupt_before_unlink(path: str, *, dir_fd: int) -> None:
                interrupted_fds.append(dir_fd)
                os.kill(os.getpid(), signum)
                real_unlink(path, dir_fd=dir_fd)

            with (
                patch.object(sys, "argv", ["packer", "--candidate", str(candidate),
                                           "--output", str(output)]),
                patch.object(packer, "ARCHIVE_LIMIT", 512),
                patch.object(packer.os, "unlink", interrupt_before_unlink),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as failure,
            ):
                packer.main()
            self.assertEqual(failure.exception.code, 2)
            self.assertEqual(len(interrupted_fds), 1)
            self.assertFalse(output.exists())
            with self.assertRaises(OSError):
                os.fstat(interrupted_fds[0])
            self.assertEqual(
                {entry.name: entry.read_bytes() for entry in candidate.iterdir()},
                trusted,
            )

    def test_archive_limit_removes_partial_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = self.make_candidate(root)
            output = root / "out.tar"
            with patch.object(packer, "ARCHIVE_LIMIT", 512), self.assertRaises(ValueError):
                packer.pack(candidate, output)
            self.assertFalse(output.exists())

    def test_short_os_reads_are_fully_packed_and_hashed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = self.make_candidate(root)
            output = root / "out.tar"
            real_read = os.read

            def short_read(fd, size):
                return real_read(fd, min(size, 3))

            with patch.object(packer.os, "read", short_read):
                result = packer.pack(candidate, output)
            self.assertEqual(result["archive_sha256"],
                             hashlib.sha256(output.read_bytes()).hexdigest())

    def test_interrupted_pack_removes_only_its_partial_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = self.make_candidate(root)
            output = root / "out.tar"
            real_read = os.read
            reads = 0

            def interrupted_read(fd, size):
                nonlocal reads
                reads += 1
                if reads > 4:
                    raise InterruptedError("terminated")
                return real_read(fd, size)

            with patch.object(packer.os, "read", interrupted_read), self.assertRaises(InterruptedError):
                packer.pack(candidate, output)
            self.assertFalse(output.exists())

    def test_caught_sigterm_removes_partial_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = self.make_candidate(root)
            output = root / "out.tar"
            real_open = os.open
            created = []

            def terminate_after_create(path, flags, *args, **kwargs):
                fd = real_open(path, flags, *args, **kwargs)
                if path == output.name and flags & os.O_EXCL:
                    created.append(output.is_file())
                    os.kill(os.getpid(), signal.SIGTERM)
                return fd

            with (
                patch.object(sys, "argv", ["packer", "--candidate", str(candidate),
                                           "--output", str(output)]),
                patch.object(packer.os, "open", terminate_after_create),
                self.assertRaises(SystemExit) as failure,
            ):
                packer.main()
            self.assertEqual(failure.exception.code, 128 + signal.SIGTERM)
            self.assertEqual(created, [True])
            self.assertFalse(output.exists())

    def test_rejects_non_finite_manifest_json(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = self.make_candidate(root)
            manifest = candidate / "candidate.json"
            manifest.write_text(manifest.read_text().replace('"schema":1', '"schema":NaN'))
            with self.assertRaises(ValueError):
                packer.pack(candidate, root / "out.tar")
            self.assertFalse((root / "out.tar").exists())


if __name__ == "__main__":
    unittest.main()
