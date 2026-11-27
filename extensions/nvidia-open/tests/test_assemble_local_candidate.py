import hashlib
import importlib.util
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

ENTRY = Path(__file__).resolve().parents[1] / "bin/assemble-local-candidate.py"
PACKER = ENTRY.with_name("pack-local-candidate.py")
SPEC = importlib.util.spec_from_file_location("assemble_local_candidate", ENTRY)
assert SPEC is not None and SPEC.loader is not None
assembler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assembler)
MODULES = ("nvidia.ko", "nvidia-drm.ko", "nvidia-modeset.ko", "nvidia-uvm.ko")
ARCHIVES = (
    "nvidia-runtime-620.70.06.tar.gz",
    "nvidia-firmware-ga10x-620.70.06.tar.gz",
    "source-and-notices.tar.gz",
)
PRODUCER = {
    "repository": "owner/repo",
    "commit": "a" * 40,
    "workflow": ".github/workflows/build.yml",
    "run_id": 1,
    "attempt": 1,
}
TARGET = {
    "version": "620.70000000.06",
    "manifest": "sha256:" + "b" * 64,
    "architecture": "x86_64",
    "kernel": "7.3.4-300.fc45.x86_64",
    "kernel_devel_sha256": "c" * 64,
}


class AssembleLocalCandidateTests(unittest.TestCase):
    def test_standalone_assembler_ignores_cancellation_signals_at_teardown(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = self.make_inputs(root / "inputs")
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            report = self.run_standalone_with_teardown_signals(
                self.command(scratch, paths), root / "assembler-report",
            )
            candidate, = scratch.iterdir()
            self.assertEqual(report, f"{candidate}\n")
            manifest = json.loads((candidate / "candidate.json").read_bytes())
            self.assertEqual(set(manifest["files"]), set(MODULES + ARCHIVES))

    def test_standalone_packer_ignores_cancellation_signals_at_teardown(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = self.make_inputs(root / "inputs")
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            assembled = subprocess.run(self.command(scratch, paths), capture_output=True,
                                       text=True, check=True, timeout=10)
            candidate = Path(assembled.stdout.strip())
            archive = root / "out.tar"
            report = self.run_standalone_with_teardown_signals(
                [sys.executable, str(PACKER), "--candidate", str(candidate), "--output", str(archive)],
                root / "packer-report",
            )
            archive_bytes = archive.read_bytes()
            self.assertEqual(json.loads(report), {
                "archive_size": len(archive_bytes),
                "archive_sha256": hashlib.sha256(archive_bytes).hexdigest(),
                "manifest_sha256": hashlib.sha256((candidate / "candidate.json").read_bytes()).hexdigest(),
            })

    def run_standalone_with_teardown_signals(self, command: list[str], report: Path) -> str:
        probe = """
import atexit
import os
import runpy
import signal
import sys

signals = (signal.SIGINT, signal.SIGTERM)

@atexit.register
def signal_at_teardown():
    if os.fstat(sys.stdout.fileno()).st_size:
        os.write(2, b"report flushed before teardown\\n")
    for signum in signals:
        if signal.getsignal(signum) == signal.SIG_IGN:
            os.write(2, f"{signum.name} ignored\\n".encode())
        signal.raise_signal(signum)

for signum in signals:
    signal.signal(signum, signal.SIG_DFL)
sys.argv.pop(0)
runpy.run_path(sys.argv[0], run_name="__main__")
"""
        with report.open("w") as stdout:
            result = subprocess.run([sys.executable, "-c", probe, *command[1:]],
                                    stdout=stdout, stderr=subprocess.PIPE,
                                    text=True, check=False, timeout=10)
        self.assertEqual(result.stderr.splitlines(), [
            "report flushed before teardown", "SIGINT ignored", "SIGTERM ignored",
        ])
        self.assertEqual(result.returncode, 0)
        return report.read_text()

    def test_signal_at_rollback_entry_preserves_failure_and_removes_candidate(self) -> None:
        self.assert_signal_at_boundary("rollback")

    def test_signal_before_commit_removes_candidate(self) -> None:
        self.assert_signal_at_boundary("before_commit")

    def test_signal_after_commit_still_reports_candidate(self) -> None:
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
                paths = self.make_inputs(root / "inputs")
                if boundary == "rollback":
                    paths[-1].unlink()
                scratch = root / "scratch"
                scratch.mkdir(mode=0o700)
                descriptors = []
                stdout = io.StringIO()
                stderr = io.StringIO()

                def trace(frame, event, arg, descriptors=descriptors, signum=signum):
                    if frame.f_code is not assembler.assemble.__code__:
                        return None
                    if event == "line" and frame.f_lineno == inject_line and not descriptors:
                        descriptors.extend(frame.f_locals[name] for name in ("output_fd", "candidate_fd"))
                        signal.raise_signal(signum)
                    return trace

                with (
                    patch.object(sys, "argv", self.command(scratch, paths)[1:]),
                    redirect_stdout(stdout),
                    redirect_stderr(stderr),
                ):
                    previous_trace = sys.gettrace()
                    sys.settrace(trace)
                    try:
                        if boundary == "after_commit":
                            assembler.main()
                        else:
                            with self.assertRaises(SystemExit) as failure:
                                assembler.main()
                            expected_code = 2 if boundary == "rollback" else 128 + signum
                            self.assertEqual(failure.exception.code, expected_code)
                    except KeyboardInterrupt:
                        self.fail("SIGINT escaped outside a cancellation checkpoint")
                    finally:
                        sys.settrace(previous_trace)
                        self.assertEqual(len(descriptors), 2)
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
                    candidate, = scratch.iterdir()
                    self.assertEqual(stdout.getvalue().strip(), str(candidate))
                    self.assertEqual({entry.name for entry in candidate.iterdir()},
                                     set(MODULES + ARCHIVES) | {"candidate.json"})
                else:
                    self.assertEqual(list(scratch.iterdir()), [])
                    self.assertEqual(stdout.getvalue(), "")
                if boundary == "rollback":
                    self.assertIn("cannot safely open input", stderr.getvalue())
                else:
                    self.assertEqual(stderr.getvalue(), "")

    def test_rollback_defers_interrupt_until_candidate_is_removed_and_closed(self) -> None:
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signum=signum):
                self.assert_rollback_defers_interrupt(signum)

    def assert_rollback_defers_interrupt(
        self, signum: signal.Signals,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = self.make_inputs(root / "inputs")
            trusted = paths[0].read_bytes()
            paths[-1].unlink()
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            real_unlink = os.unlink
            interrupted_fds: list[int] = []

            def interrupt_before_unlink(path: str, *, dir_fd: int) -> None:
                if not interrupted_fds:
                    interrupted_fds.append(dir_fd)
                    os.kill(os.getpid(), signum)
                real_unlink(path, dir_fd=dir_fd)

            with (
                patch.object(sys, "argv", self.command(scratch, paths)[1:]),
                patch.object(assembler.os, "unlink", interrupt_before_unlink),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as failure,
            ):
                assembler.main()
            self.assertEqual(failure.exception.code, 2)
            self.assertEqual(len(interrupted_fds), 1)
            self.assertEqual(list(scratch.iterdir()), [])
            with self.assertRaises(OSError):
                os.fstat(interrupted_fds[0])
            self.assertEqual(paths[0].read_bytes(), trusted)

    def test_caught_sigterm_removes_new_candidate_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = self.make_inputs(root / "inputs")
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            real_mkdir = os.mkdir

            def terminate_after_mkdir(path: str, mode: int, *, dir_fd: int) -> None:
                real_mkdir(path, mode, dir_fd=dir_fd)
                os.kill(os.getpid(), signal.SIGTERM)

            with (
                patch.object(sys, "argv", self.command(scratch, paths)[1:]),
                patch.object(assembler.os, "mkdir", terminate_after_mkdir),
                self.assertRaises(SystemExit) as failure,
            ):
                assembler.main()
            self.assertEqual(failure.exception.code, 128 + signal.SIGTERM)
            self.assertEqual(list(scratch.iterdir()), [])

    def test_copies_exact_inputs_and_claims_match_copied_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            inputs = root / "inputs"
            inputs.mkdir()
            paths = []
            contents = {}
            for name in MODULES + ARCHIVES:
                paths.append(inputs / name)
                contents[name] = ("payload:" + name).encode()
                paths[-1].write_bytes(contents[name])
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            command = ["python3", str(ENTRY), "--output", str(scratch),
                       "--producer", json.dumps(PRODUCER), "--target", json.dumps(TARGET)]
            for name, path in zip(MODULES + ARCHIVES, paths):
                command.extend(("--file", f"{name}={path}"))
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            candidate = Path(result.stdout.strip())
            self.assertEqual({p.name for p in candidate.iterdir()},
                             set(MODULES + ARCHIVES + ("candidate.json",)))
            document = json.loads((candidate / "candidate.json").read_text())
            self.assertEqual(document["schema"], 1)
            self.assertEqual(document["producer"], PRODUCER)
            self.assertEqual(document["target"], TARGET)
            for name, content in contents.items():
                self.assertEqual((candidate / name).read_bytes(), content)
                self.assertEqual(document["files"][name], {
                    "size": len(content), "sha256": hashlib.sha256(content).hexdigest()
                })
            self.assertEqual(candidate.stat().st_mode & 0o777, 0o700)
            self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600
                                for path in candidate.iterdir()))

    def test_assembler_output_packs_until_payload_bytes_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            assembled = subprocess.run(
                self.command(scratch, self.make_inputs(root / "inputs")),
                capture_output=True, text=True, check=True, timeout=3,
            )
            candidate = Path(assembled.stdout.strip())
            output = scratch / "first.tar"
            command = ["python3", str(PACKER), "--candidate", str(candidate), "--output", str(output)]
            packed = subprocess.run(command, capture_output=True, text=True, check=True, timeout=3)
            report = json.loads(packed.stdout)
            self.assertEqual(report["archive_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
            self.assertEqual(report["manifest_sha256"],
                             hashlib.sha256((candidate / "candidate.json").read_bytes()).hexdigest())

            modified = candidate / MODULES[0]
            modified.write_bytes(b"x" * modified.stat().st_size)
            rejected = scratch / "rejected.tar"
            command[-1] = str(rejected)
            failed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=3)
            self.assertEqual(failed.returncode, 2, failed.stderr)
            self.assertIn("candidate bytes do not match stable manifest claim", failed.stderr)
            self.assertFalse(rejected.exists())

    def test_rejects_missing_and_extra_inputs_without_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            inputs = root / "inputs"
            inputs.mkdir()
            for name in MODULES + ARCHIVES[:-1]:
                (inputs / name).write_bytes(b"x")
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            command = ["python3", str(ENTRY), "--output", str(scratch),
                       "--producer", json.dumps(PRODUCER), "--target", json.dumps(TARGET)]
            for name in MODULES + ARCHIVES[:-1]:
                command.extend(("--file", f"{name}={inputs / name}"))
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(scratch.iterdir()), [])

    def test_rejects_extra_and_duplicate_names(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = self.make_inputs(root)
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            command = self.command(scratch, paths)
            command.extend(("--file", f"unexpected={paths[0]}"))
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(scratch.iterdir()), [])
            command = self.command(scratch, paths)
            command.extend(("--file", f"{MODULES[0]}={paths[0]}"))
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(scratch.iterdir()), [])

    def test_rejects_symlink_fifo_and_hardlink_sources(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            for kind in ("symlink", "fifo", "hardlink"):
                paths = self.make_inputs(root / kind)
                target = paths[0]
                if kind == "symlink":
                    alt = target.with_name("alternate")
                    alt.symlink_to(target)
                elif kind == "fifo":
                    alt = target.with_name("alternate")
                    os.mkfifo(alt)
                else:
                    alt = target.with_name("alternate")
                    os.link(target, alt)
                paths[0] = alt
                result = subprocess.run(self.command(scratch, paths),
                                        capture_output=True, text=True, timeout=3, check=False)
                self.assertNotEqual(result.returncode, 0, kind)
                self.assertEqual(list(scratch.iterdir()), [])

    def test_rejects_duplicate_identity_json_keys(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = self.make_inputs(root)
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            command = self.command(scratch, paths)
            command[command.index("--producer") + 1] = (
                '{"repository":"owner/repo","repository":"evil/repo",'
                '"commit":"' + "a" * 40 + '","workflow":".github/workflows/build.yml",'
                '"run_id":1,"attempt":1}'
            )
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(scratch.iterdir()), [])

    def test_rejects_non_private_output_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = self.make_inputs(root)
            scratch = root / "scratch"
            scratch.mkdir(mode=0o755)
            result = subprocess.run(self.command(scratch, paths),
                                    capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(scratch.iterdir()), [])

    def test_rejects_oversized_file_and_oversized_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = self.make_inputs(root)
            with paths[0].open("wb") as stream:
                stream.truncate((128 << 20) + 1)
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            result = subprocess.run(self.command(scratch, paths),
                                    capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(scratch.iterdir()), [])
            command = self.command(scratch, self.make_inputs(root / "small"))
            command[command.index("--producer") + 1] = json.dumps(
                PRODUCER | {"repository": "x" * 17000}
            )
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(scratch.iterdir()), [])

    @staticmethod
    def make_inputs(root: Path) -> list[Path]:
        root.mkdir(parents=True, exist_ok=True)
        paths = []
        for name in MODULES + ARCHIVES:
            path = root / name
            path.write_bytes(("payload:" + name).encode())
            paths.append(path)
        return paths

    @staticmethod
    def command(scratch: Path, paths: list[Path]) -> list[str]:
        command = ["python3", str(ENTRY), "--output", str(scratch),
                   "--producer", json.dumps(PRODUCER), "--target", json.dumps(TARGET)]
        command.extend(part for name, path in zip(MODULES + ARCHIVES, paths)
                       for part in ("--file", f"{name}={path}"))
        return command


if __name__ == "__main__":
    unittest.main()
