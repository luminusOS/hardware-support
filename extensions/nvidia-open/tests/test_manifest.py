#!/usr/bin/env python3
"""Self-consistency tests for the curation manifest (no vendor archive needed)."""

import json
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST_PATH = os.path.join(HERE, "..", "manifests", "nvidia-620.70.06.json")

with open(MANIFEST_PATH, encoding="utf-8") as fh:
    M = json.load(fh)


def pkg_by_name(name):
    return next(p for p in M["packages"] if p["name"] == name)


class ManifestTests(unittest.TestCase):
    def test_schema_and_pins(self):
        self.assertEqual(M["schema"], "luminusos.nvidia-packaging/1")
        va = M["vendor_archive"]
        self.assertRegex(va["sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(va["license_sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(va["url"].startswith("https://download.nvidia.com/"))
        self.assertEqual(M["driver_version"], "620.70.06")
        self.assertEqual(pkg_by_name("nvidia-runtime")["version"], M["driver_version"])
        self.assertEqual(pkg_by_name("nvidia-firmware-ga10x")["version"], M["driver_version"])

    def test_install_paths_are_relative_and_safe(self):
        for p in M["packages"]:
            for spec in p["files"]:
                self.assertFalse(spec["install"].startswith("/"), spec["install"])
                self.assertNotIn("..", spec["install"].split("/"), spec["install"])
                self.assertFalse(spec["archive"].startswith("32/"), spec["archive"])
                self.assertNotIn("/32/", "/" + spec["archive"])

    def test_every_file_resolves(self):
        for p in M["packages"]:
            file_names = {os.path.basename(s["install"]) for s in p["files"]}
            link_names = {os.path.basename(s["install"]) for s in p.get("symlinks", [])}
            for spec in p.get("symlinks", []):
                tgt = os.path.basename(spec["target"])
                full = os.path.normpath(os.path.join(os.path.dirname(spec["install"]), spec["target"]))
                full_base = os.path.basename(full)
                self.assertTrue(
                    tgt in file_names or tgt in link_names or full_base in file_names or full_base in link_names,
                    f"{spec['install']} -> {spec['target']} has no landing file")
            for spec in p["files"]:
                ref = spec.get("references")
                if ref:
                    self.assertIn(ref, file_names | link_names,
                                  f"{spec['install']} references {ref}, not packaged")

    def test_loader_conflicts_never_declared(self):
        import fnmatch
        for p in M["packages"]:
            names = {os.path.basename(s["install"]) for s in p["files"]}
            names |= {os.path.basename(s["install"]) for s in p.get("symlinks", [])}
            for pattern in M["loader_conflicts"]:
                for n in names:
                    self.assertFalse(fnmatch.fnmatch(n, pattern),
                                     f"{n} matches forbidden loader pattern {pattern}")

    def test_no_vendor_library_in_system_allows(self):
        for entry in M["system_allows"]:
            name = entry["soname"] if isinstance(entry, dict) else entry
            self.assertFalse(name.startswith(("libnvidia-", "libGLX_nvidia", "libEGL_nvidia")),
                             f"vendor library {name} must be curated as a package file")

    def test_system_allows_fully_justified(self):
        import fnmatch
        allowed_verified = {
            "target-image-inventory-2026-11-22",
        }
        for entry in M["system_allows"]:
            self.assertIsInstance(entry, dict, "allow entries must carry evidence")
            self.assertRegex(entry.get("provider", ""), r"^[A-Za-z0-9._+-]+\.fc\d+\.",
                             f"provider must be an exact NVR from guest inventory: {entry}")
            self.assertIn(entry.get("verified"), allowed_verified, str(entry))
            if "verified_note" in entry:
                self.assertIsInstance(entry["verified_note"], str, str(entry))
            for pattern in M["loader_conflicts"]:
                self.assertFalse(fnmatch.fnmatch(entry["soname"], pattern),
                                 f"loader namespace {entry['soname']} may never be allowed as a "
                                 "base dependency — DT_NEEDED onto loaders is a Mesa-stack risk")
        self.assertNotIn("libresolv.so.1", [e["soname"] for e in M["system_allows"]])
        self.assertNotIn("libnsl.so.1", [e["soname"] for e in M["system_allows"]])

    def test_exclusions_never_mask_packaged_files(self):
        import fnmatch
        for p in M["packages"]:
            installed = {os.path.basename(s["install"]) for s in p["files"]}
            patterns = [spec["pattern"] for spec in p.get("dlopen_excludes", [])]
            patterns += [spec["pattern"] for spec in p.get("loader_reference_excludes", [])]
            for name in installed:
                for pat in patterns:
                    self.assertIsNone(re.match(pat, name),
                                      f"installed file {name} must not be covered by exclusion {pat}")

    def test_loader_reference_excludes_sane(self):
        for p in M["packages"]:
            for spec in p.get("loader_reference_excludes", []):
                re.compile(spec["pattern"])
                self.assertTrue(spec.get("reason"), spec["pattern"])

    def test_gpucomp_is_packaged_not_excluded(self):
        rt = pkg_by_name("nvidia-runtime")
        self.assertTrue(any(s["archive"] == "libnvidia-gpucomp.so.620.70.06" for s in rt["files"]),
                        "guest build proved libnvidia-eglcore/glcore DT_NEED gpucomp; it must ship")

    def test_dlopen_excludes_compile(self):
        for p in M["packages"]:
            for spec in p.get("dlopen_excludes", []):
                re.compile(spec["pattern"])
                self.assertTrue(spec.get("reason"), spec["pattern"])

    def test_firmware_layout_matches_module_rule(self):
        fw = pkg_by_name("nvidia-firmware-ga10x")
        ver = M["driver_version"]
        self.assertEqual(fw["declared_by_module"], ["gsp_ga10x", "ucodes_ga10x"])
        for spec in fw["files"]:
            if spec["archive"].startswith("firmware/"):
                self.assertEqual(spec["install"],
                                 f"usr/lib/firmware/nvidia/{ver}/{os.path.basename(spec['archive'])}")
                self.assertRegex(spec["archive"], r"ga10x")
        self.assertEqual({s["archive"] for s in fw["excluded"]},
                         {"firmware/gsp_tu10x.bin", "firmware/ucodes_tu10x.bin"})

    def test_licensed_packages_ship_license(self):
        for p in M["packages"]:
            self.assertTrue(any(s["archive"] == "LICENSE" for s in p["files"]),
                            f"{p['name']} missing LICENSE")

    def test_runtime_domains_covered(self):
        rt = pkg_by_name("nvidia-runtime")
        installs = " ".join(s["install"] for s in rt["files"])
        for need in ["egl_vendor.d/10_nvidia.json", "egl_external_platform.d/15_nvidia_gbm.json",
                     "vulkan/icd.d/nvidia_icd.json", "libGLX_nvidia.so.620.70.06",
                     "libnvidia-ml.so.620.70.06", "bin/nvidia-smi"]:
            self.assertIn(need, installs)


if __name__ == "__main__":
    unittest.main(verbosity=2)
