import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ENTRY = Path(__file__).resolve().parents[1] / "bin/build-candidate.sh"


class BuildCandidateTests(unittest.TestCase):
    def test_bad_archive_cannot_leave_candidate_or_work_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "vendor archive.run"
            archive.write_text("not the pinned NVIDIA archive")
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            result = subprocess.run(
                ["bash", ENTRY, archive, scratch],
                env=os.environ | {"SKIP_DOWNLOAD": "0"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SHA-256 mismatch for vendor archive", result.stderr)
            self.assertEqual(list(scratch.iterdir()), [])

    def test_missing_archive_is_refused_without_creating_scratch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            result = subprocess.run(
                ["bash", ENTRY, root / "missing.run", scratch],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("expected an existing vendor archive", result.stderr)
            self.assertEqual(list(scratch.iterdir()), [])

    def test_shared_scratch_is_refused_before_running_packager(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "vendor.run"
            archive.write_text("not the pinned NVIDIA archive")
            scratch = root / "scratch"
            scratch.mkdir()
            scratch.chmod(0o755)
            result = subprocess.run(
                ["bash", ENTRY, archive, scratch],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "scratch must be an owned directory with mode 0700", result.stderr
            )
            self.assertEqual(list(scratch.iterdir()), [])
