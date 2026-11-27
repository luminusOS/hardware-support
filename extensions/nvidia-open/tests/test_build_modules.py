import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ENTRY = Path(__file__).resolve().parents[1] / "bin/build-modules.sh"


class BuildModulesTests(unittest.TestCase):
    def test_unpinned_source_fails_without_running_build_or_leaving_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.tar.gz"
            source.write_text("not the pinned source")
            rpm = root / "kernel-devel.rpm"
            rpm.touch()
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            tools = root / "tools"
            tools.mkdir()
            make = tools / "make"
            marker = root / "called-make"
            make.write_text('#!/bin/sh\ntouch -- "$BUILD_TEST_MARKER"\n')
            make.chmod(0o755)
            result = subprocess.run(
                ["bash", ENTRY, source, rpm, scratch],
                env=os.environ
                | {
                    "PATH": f"{tools}:{os.environ['PATH']}",
                    "BUILD_TEST_MARKER": str(marker),
                },
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("source SHA-256 mismatch", result.stderr)
            self.assertFalse(marker.exists())
            self.assertEqual(list(scratch.iterdir()), [])
