#!/usr/bin/env python3
"""Unit tests for linkcheck.py using synthetic ELF64 fixtures (no vendor data)."""

import importlib.util
import json
import os
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location("linkcheck", os.path.join(HERE, "..", "bin", "linkcheck.py"))
linkcheck = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(linkcheck)


def make_elf(needed=(), soname=None):
    """Minimal ELF64 LSB x86-64 with PT_LOAD identity mapping + PT_DYNAMIC."""
    strings = []
    for s in list(needed) + ([soname] if soname else []):
        strings.append(s)
    strtab = b"\0" + b"".join(s.encode() + b"\0" for s in strings)
    str_off = {}
    pos = 1
    for s in strings:
        str_off[s] = pos
        pos += len(s) + 1

    n_ph = 2
    hdr = 64
    phsz = 56 * n_ph
    load_off = hdr + phsz
    str_abs = load_off + 64  # gap for fake .text
    dyn_abs = str_abs + len(strtab)
    entries = []
    for s in needed:
        entries.append((linkcheck.DT_NEEDED, str_off[s]))
    if soname:
        entries.append((linkcheck.DT_SONAME, str_off[soname]))
    entries.append((linkcheck.DT_STRTAB, str_abs))
    entries.append((linkcheck.DT_STRSZ, len(strtab)))
    entries.append((linkcheck.DT_NULL, 0))
    dyn_body = b"".join(struct.pack("<QQ", t, v) for t, v in entries)
    dyn_len = len(dyn_body)
    total = dyn_abs + dyn_len

    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2
    ehdr[5] = 1
    ehdr[6] = 1
    struct.pack_into("<HHIQQQIHHHHHH", ehdr, 16,
                     2, 62, 1, 0, hdr, 0, 0, 64, 56, n_ph, 0, 0, 0)
    def phdr(p_type, off, size):
        return struct.pack("<IIQQQQQQ", p_type, 5, off, off, off, size, size, 0x5)
    ph = phdr(linkcheck.PT_LOAD, 0, total) + phdr(linkcheck.PT_DYNAMIC, dyn_abs, dyn_len)
    body = b"\x90" * 64 + strtab + dyn_body
    return bytes(ehdr) + ph + body


BASE_MANIFEST = {
    "driver_version": "620.70.06",
    "system_allows": ["libc.so.6", "libdl.so.2"],
    "loader_conflicts": ["libEGL.so*", "libGL.so*", "libGLX.so*"],
    "packages": [],
}


def pkg(files, symlinks=None, registrations=None, excludes=None):
    entries = list(files)
    for spec in registrations or []:
        entries.append(spec)
    return {"name": "nvidia-runtime", "version": "620.70.06", "files": entries,
            "symlinks": symlinks or [], "dlopen_excludes": excludes or []}


def write_tree(root, elfs, plain=None, links=None):
    for rel, blob in elfs.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(blob)
    for rel, text in (plain or {}).items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
    for rel, target in (links or {}).items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if not os.path.lexists(p):
            os.symlink(target, p)


class LinkcheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def check(self, manifest, pkg):
        files, links = linkcheck.load_staged_tree(self.root)
        c = linkcheck.Checker(manifest, self.root, files, links)
        c.run(pkg)
        return c

    def test_elf_parser_roundtrip(self):
        blob = make_elf(needed=["libc.so.6", "libfoo.so.1"], soname="libbar.so.1")
        needed, soname = linkcheck.elf_dynamic(blob)
        self.assertEqual(needed, ["libc.so.6", "libfoo.so.1"])
        self.assertEqual(soname, "libbar.so.1")

    def test_firmware_blobs_are_out_of_elf_scope(self):
        riscv = bytearray(make_elf(needed=["libc.so.6"]))
        struct.pack_into("<H", riscv, 18, 243)  # e_machine = EM_RISCV (like gsp_ga10x.bin)
        write_tree(self.root, {"usr/lib/firmware/nvidia/620.70.06/gsp_ga10x.bin": bytes(riscv)})
        m = dict(BASE_MANIFEST)
        p = {"name": "nvidia-firmware-ga10x", "version": "620.70.06",
             "files": [{"archive": "firmware/gsp_ga10x.bin",
                        "install": "usr/lib/firmware/nvidia/620.70.06/gsp_ga10x.bin", "mode": "0644"}]}
        c = self.check(m, p)
        self.assertEqual([e for e in c.errors if "elf" in e], [])

    def test_clean_tree_passes(self):
        write_tree(self.root, {
            "usr/lib64/libA.so.620.70.06": make_elf(needed=["libB.so.620.70.06", "libc.so.6"], soname="libA.so.1"),
            "usr/lib64/libB.so.620.70.06": make_elf(needed=["libc.so.6"], soname="libB.so.620.70.06"),
        }, links={"usr/lib64/libA.so.1": "libA.so.620.70.06"})
        m = dict(BASE_MANIFEST)
        p = pkg([
            {"archive": "libA.so.620.70.06", "install": "usr/lib64/libA.so.620.70.06", "mode": "0755"},
            {"archive": "libB.so.620.70.06", "install": "usr/lib64/libB.so.620.70.06", "mode": "0755"},
        ], symlinks=[{"install": "usr/lib64/libA.so.1", "target": "libA.so.620.70.06"}])
        c = self.check(m, p)
        self.assertEqual(c.errors, [], msg=str(c.errors))

    def test_unresolved_vendor_needed_fails(self):
        write_tree(self.root, {
            "usr/lib64/libA.so.620.70.06": make_elf(needed=["libMISSING.so.620.70.06"]),
        })
        m = dict(BASE_MANIFEST)
        p = pkg([{"archive": "libA.so.620.70.06", "install": "usr/lib64/libA.so.620.70.06", "mode": "0755"}])
        c = self.check(m, p)
        self.assertTrue(any("unresolved DT_NEEDED" in e and "libMISSING" in e for e in c.errors))

    def test_loader_conflict_fails(self):
        write_tree(self.root, {
            "usr/lib64/libA.so.620.70.06": make_elf(needed=["libc.so.6"]),
            "usr/lib64/libEGL.so.1.1.0": make_elf(needed=["libc.so.6"]),
        })
        m = dict(BASE_MANIFEST)
        p = pkg([
            {"archive": "libA.so.620.70.06", "install": "usr/lib64/libA.so.620.70.06", "mode": "0755"},
            {"archive": "libEGL.so.1.1.0", "install": "usr/lib64/libEGL.so.1.1.0", "mode": "0755"},
        ])
        c = self.check(m, p)
        self.assertTrue(any("loader-conflict" in e for e in c.errors))

    def test_broken_symlink_target_fails(self):
        write_tree(self.root, {
            "usr/lib64/libA.so.620.70.06": make_elf(needed=["libc.so.6"]),
        }, links={"usr/lib64/libA.so.1": "libGONE.so.620.70.06"})
        m = dict(BASE_MANIFEST)
        p = pkg([{"archive": "libA.so.620.70.06", "install": "usr/lib64/libA.so.620.70.06", "mode": "0755"}],
                symlinks=[{"install": "usr/lib64/libA.so.1", "target": "libGONE.so.620.70.06"}])
        c = self.check(m, p)
        self.assertTrue(any("target does not resolve" in e for e in c.errors))

    def test_registration_reference_mismatch_fails(self):
        write_tree(self.root, {
            "usr/lib64/libA.so.620.70.06": make_elf(needed=["libc.so.6"]),
        }, plain={"usr/share/glvnd/egl_vendor.d/10_a.json":
                  json.dumps({"file_format_version": "1.0.0", "ICD": {"library_path": "libA.so.1"}})},
           links={"usr/lib64/libA.so.1": "libA.so.620.70.06"})
        m = dict(BASE_MANIFEST)
        p = pkg([{"archive": "libA.so.620.70.06", "install": "usr/lib64/libA.so.620.70.06", "mode": "0755"}],
                symlinks=[{"install": "usr/lib64/libA.so.1", "target": "libA.so.620.70.06"}],
                registrations=[{"archive": "10_a.json",
                                "install": "usr/share/glvnd/egl_vendor.d/10_a.json",
                                "mode": "0644", "references": "libWRONG.so.1"}])
        c = self.check(m, p)
        self.assertTrue(any("!= manifest reference" in e for e in c.errors))

    def test_registration_reference_unpackaged_fails(self):
        write_tree(self.root, {
            "usr/lib64/libA.so.620.70.06": make_elf(needed=["libc.so.6"]),
        }, plain={"usr/share/vulkan/icd.d/a_icd.json":
                  json.dumps({"file_format_version": "1.0.1", "ICD": {"library_path": "libZ.so.0"}})},
           links={})
        m = dict(BASE_MANIFEST)
        p = pkg([{"archive": "libA.so.620.70.06", "install": "usr/lib64/libA.so.620.70.06", "mode": "0755"}],
                registrations=[{"archive": "a_icd.json",
                                "install": "usr/share/vulkan/icd.d/a_icd.json",
                                "mode": "0644", "references": "libZ.so.0"}])
        c = self.check(m, p)
        self.assertTrue(any("is not packaged" in e for e in c.errors))

    def test_dlopen_audit_requires_declaration(self):
        payload = make_elf(needed=["libc.so.6"]) + b"\0libcuda.so.1\0"
        write_tree(self.root, {"usr/lib64/libA.so.620.70.06": payload})
        vman = os.path.join(self.tmp.name, ".vendor.manifest")
        with open(vman, "w", encoding="utf-8") as fh:
            fh.write("libcuda.so.620.70.06 0755 CUDA_LIB NATIVE / MODULE:gpgpu\n"
                     "libcuda.so.1 0000 CUDA_SYMLINK NATIVE libcuda.so.620.70.06 MODULE:gpgpu\n")
        m = dict(BASE_MANIFEST)
        p = pkg([{"archive": "libA.so.620.70.06", "install": "usr/lib64/libA.so.620.70.06", "mode": "0755"}])
        c = linkcheck.Checker(m, self.root, *linkcheck.load_staged_tree(self.root), vendor_manifest=vman)
        c.run(p)
        self.assertTrue(any("dlopen-audit" in e and "libcuda.so.1" in e for e in c.errors),
                        msg=str(c.errors))

        p2 = pkg([{"archive": "libA.so.620.70.06", "install": "usr/lib64/libA.so.620.70.06", "mode": "0755"}],
                 excludes=[{"pattern": "^libcuda\\.so", "reason": "CUDA not in pilot domains"}])
        c2 = linkcheck.Checker(m, self.root, *linkcheck.load_staged_tree(self.root), vendor_manifest=vman)
        c2.run(p2)
        self.assertFalse(any("dlopen-audit" in e for e in c2.errors), msg=str(c2.errors))


if __name__ == "__main__":
    unittest.main(verbosity=2)
