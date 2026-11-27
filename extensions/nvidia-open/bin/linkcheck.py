#!/usr/bin/env python3
"""Verify that a staged NVIDIA runtime tree is link-safe against its manifest.

Pure-Python ELF64 parser (no binutils dependency). Checks, in order:
  1. every packaged ELF is 64-bit x86-64;
  2. every DT_NEEDED resolves to a packaged file/symlink or the system allowlist;
  3. declared symlinks exist and their targets exist (chains <= 2 hops);
  4. every registration json "library_path"/"references" resolves in the package;
  5. no loader-side (glvnd/Mesa) file matches loader_conflict patterns;
  6. dlopen audit: every vendor-library name string found inside packaged
     binaries is either packaged or covered by a declared dlopen_excludes rule;
  7. version pairing: driver-suffixed files end in the manifest driver version.

Exit 0 when the tree passes; 1 with a report of every violation otherwise.
"""

import argparse
import fnmatch
import json
import os
import re
import struct
import sys

DT_NULL = 0
DT_NEEDED = 1
DT_SONAME = 14
DT_STRTAB = 5
DT_STRSZ = 10
PT_LOAD = 1
PT_DYNAMIC = 2
EM_X86_64 = 62
ELFCLASS64 = 2
ELFDATA2LSB = 1

VENDOR_LIB_RE = re.compile(rb"(lib[A-Za-z0-9_][A-Za-z0-9_.\-]*\.so(?:\.[0-9A-Za-z][0-9A-Za-z.]*)?)")


class ParseError(Exception):
    pass


def elf_dynamic(data: bytes):
    """Return (needed: list[str], soname: str|None) for an ELF64 little-endian image."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ParseError("not an ELF file")
    if data[4] != ELFCLASS64 or data[5] != ELFDATA2LSB:
        raise ParseError(f"unsupported ELF class/endianness (class={data[4]}, endian={data[5]})")
    e_machine = struct.unpack_from("<H", data, 18)[0]
    if e_machine != EM_X86_64:
        raise ParseError(f"unexpected e_machine {e_machine} (want x86-64)")
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize = struct.unpack_from("<H", data, 54)[0]
    e_phnum = struct.unpack_from("<H", data, 56)[0]

    loads = []
    dynamic = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        p_offset = struct.unpack_from("<Q", data, off + 8)[0]
        p_vaddr = struct.unpack_from("<Q", data, off + 16)[0]
        p_filesz = struct.unpack_from("<Q", data, off + 32)[0]
        if p_type == PT_LOAD:
            loads.append((p_vaddr, p_offset, p_filesz))
        elif p_type == PT_DYNAMIC:
            dynamic = (p_offset, p_filesz)
    if dynamic is None:
        raise ParseError("no PT_DYNAMIC (statically linked or not shared object)")

    def v2o(vaddr):
        for vaddr_s, off_s, sz_s in loads:
            if vaddr_s <= vaddr < vaddr_s + sz_s:
                return off_s + (vaddr - vaddr_s)
        return None

    dyn_off, dyn_sz = dynamic
    strtab_off = None
    needed_offsets = []
    soname_off = None
    pos = dyn_off
    end = dyn_off + dyn_sz
    while pos + 16 <= end:
        d_tag, d_val = struct.unpack_from("<QQ", data, pos)
        pos += 16
        if d_tag == DT_NULL:
            break
        if d_tag == DT_STRTAB:
            strtab_off = v2o(d_val)
        elif d_tag == DT_NEEDED:
            needed_offsets.append(d_val)
        elif d_tag == DT_SONAME:
            soname_off = d_val
    if strtab_off is None:
        raise ParseError("no DT_STRTAB")

    def cstr(voff):
        start = strtab_off + voff
        stop = data.index(b"\0", start)
        return data[start:stop].decode("utf-8", "replace")

    return [cstr(o) for o in needed_offsets], (cstr(soname_off) if soname_off else None)


def load_staged_tree(root: str):
    """Return (files: set[relpath], symlinks: dict[relpath -> target], elfs: list)."""
    files, symlinks = set(), {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames + dirnames:
            p = os.path.join(dirpath, name)
            rel = os.path.relpath(p, root)
            if os.path.islink(p):
                symlinks[rel] = os.readlink(p)
            else:
                files.add(rel)
    return files, symlinks


class Checker:
    def __init__(self, manifest, root, staged_files, staged_links, vendor_manifest=None):
        self.m = manifest
        self.root = root
        self.staged_files = staged_files
        self.staged_links = staged_links
        self.vendor_manifest = vendor_manifest or ""
        self.version = manifest["driver_version"]
        self.errors = []
        self.warnings = []
        self.notes = []
        self.basenames = {os.path.basename(f) for f in staged_files}
        self.link_names = {os.path.basename(k) for k in staged_links}
        self.resolvable = self.basenames | self.link_names
        self.system_allows = set()
        for entry in manifest["system_allows"]:
            if isinstance(entry, dict):
                self.system_allows.add(entry["soname"])
            else:
                self.system_allows.add(entry)
        self.link_report = {}

    def err(self, where, msg):
        self.errors.append(f"{where}: {msg}")

    def resolve_needed(self, name):
        for pattern in self.m["loader_conflicts"]:
            if fnmatch.fnmatch(name, pattern):
                return None
        if name in self.basenames:
            return "package-file"
        if name in self.link_names:
            return "package-symlink"
        if name in self.system_allows:
            return "system"
        return None

    def check_symlinks(self, pkg):
        for spec in pkg.get("symlinks", []):
            rel = spec["install"]
            if rel not in self.staged_links:
                self.err("symlinks", f"declared symlink missing from staging: {rel}")
                continue
            actual = self.staged_links[rel]
            if actual != spec["target"]:
                self.err("symlinks", f"{rel}: target {actual!r} != manifest {spec['target']!r}")
            base_dir = os.path.dirname(rel)
            target_rel = os.path.normpath(os.path.join(base_dir, spec["target"]))
            hops = 0
            while target_rel in self.staged_links and hops < 2:
                nxt = self.staged_links[target_rel]
                target_rel = os.path.normpath(os.path.join(os.path.dirname(target_rel), nxt))
                hops += 1
            if target_rel in self.staged_links:
                self.err("symlinks", f"{rel}: symlink chain deeper than 2 hops")
            elif target_rel not in self.staged_files:
                self.err("symlinks", f"{rel}: target does not resolve to a packaged file ({target_rel})")

    def check_elf_deps(self):
        for rel in sorted(self.staged_files):
            p = os.path.join(self.root, rel)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            if rel.startswith("usr/lib/firmware/"):
                continue  # GPU-side blobs (gsp_ga10x.bin is itself a RISC-V ELF); not host-linked
            with open(p, "rb") as fh:
                head = fh.read(4)
                if head != b"\x7fELF":
                    continue
                fh.seek(0)
                data = fh.read()
            try:
                needed, soname = elf_dynamic(data)
            except ParseError as exc:
                self.err("elf", f"{rel}: {exc}")
                continue
            self.link_report[rel] = {"needed": needed, "soname": soname}
            for dep in needed:
                for pattern in self.m["loader_conflicts"]:
                    if fnmatch.fnmatch(dep, pattern):
                        self.err("loader-conflict",
                                 f"{rel}: DT_NEEDED {dep!r} links the GLVND/Mesa loader namespace; "
                                 "vendor runtime must not hard-link loader libraries")
                if not self.resolve_needed(dep):
                    hint = ""
                    if dep.startswith(("libnvidia-", "libEGL_nvidia", "libGLX_nvidia", "libGLESv")):
                        hint = " (vendor library not curated — add to manifest files/symlinks)"
                    self.err("needed", f"{rel}: unresolved DT_NEEDED {dep!r}{hint}")
            # loader conflict must never appear as a real file
            for pattern in self.m["loader_conflicts"]:
                if fnmatch.fnmatch(os.path.basename(rel), pattern):
                    self.err("loader-conflict",
                             f"{rel} matches forbidden loader pattern {pattern!r} "
                             "(would replace the Mesa/glvnd stack)")

    def check_links_not_loaders(self, pkg):
        for spec in pkg.get("symlinks", []):
            for pattern in self.m["loader_conflicts"]:
                if fnmatch.fnmatch(os.path.basename(spec["install"]), pattern):
                    self.err("loader-conflict",
                             f"declared symlink {spec['install']} matches forbidden pattern {pattern!r}")

    def check_registrations(self, pkg):
        for spec in pkg["files"]:
            ref = spec.get("references")
            if not ref:
                continue
            install = spec["install"]
            if install not in self.staged_files:
                self.err("registration", f"missing json {install}")
                continue
            with open(os.path.join(self.root, install), "rb") as fh:
                blob = json.loads(fh.read())
            lib = blob.get("ICD", {}).get("library_path") or blob.get("library_path")
            if lib != ref:
                self.err("registration",
                         f"{install}: json library_path {lib!r} != manifest reference {ref!r}")
            if lib not in self.resolvable:
                self.err("registration", f"{install}: referenced library {lib!r} is not packaged")

    def check_dlopen_audit(self, pkg):
        universe = self._archive_lib_names(pkg)
        exclude_res = [(re.compile(spec["pattern"]), spec["reason"])
                       for spec in pkg.get("dlopen_excludes", [])]
        exclude_res += [(re.compile(spec["pattern"]), spec["reason"])
                        for spec in pkg.get("loader_reference_excludes", [])]
        for rel in sorted(self.staged_files):
            if rel not in self.link_report:
                continue
            with open(os.path.join(self.root, rel), "rb") as fh:
                data = fh.read()
            candidates = {c.decode() for c in VENDOR_LIB_RE.findall(data)}
            for name in sorted(candidates & universe):
                if self.resolve_needed(name):
                    continue
                if any(rx.match(name) for rx, _ in exclude_res):
                    continue
                self.err("dlopen-audit",
                         f"{rel} references vendor library {name!r} that is neither packaged "
                         "nor covered by an explicit dlopen_excludes rule")

    def _archive_lib_names(self, pkg):
        names = set()
        if self.vendor_manifest and os.path.exists(self.vendor_manifest):
            with open(self.vendor_manifest, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parts = line.split()
                    if parts and ".so" in parts[0]:
                        names.add(os.path.basename(parts[0].lstrip("./")))
        for spec in pkg["files"]:
            arch = os.path.basename(spec["archive"])
            if ".so" in arch:
                names.add(arch)
        return names

    def check_version_pairing(self, pkg):
        suffix = "." + self.version
        for spec in pkg["files"]:
            base = os.path.basename(spec["install"])
            arch = os.path.basename(spec["archive"])
            if arch.endswith(suffix):
                if base != arch:
                    self.err("version-pairing", f"install name {base} drifted from archive name {arch}")
                self.notes.append(f"driver-versioned: {arch}")
            elif re.search(r"\.so\.\d+\.\d+\.\d+$", arch):
                self.warnings.append(
                    f"external-platform library with its own upstream versioning: {arch}")
        if pkg["name"].startswith("nvidia-firmware"):
            for spec in pkg["files"]:
                if spec["archive"].startswith("firmware/"):
                    fw_dir = spec["install"].split("/")[-2]
                    if fw_dir != self.version:
                        self.err("version-pairing",
                                 f"{spec['archive']}: firmware directory segment {fw_dir!r} "
                                 f"!= driver version {self.version}")

    def run(self, pkg):
        self.check_links_not_loaders(pkg)
        self.check_symlinks(pkg)
        self.check_elf_deps()
        self.check_registrations(pkg)
        self.check_dlopen_audit(pkg)
        self.check_version_pairing(pkg)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--pkg", required=True, help="package name inside the manifest")
    ap.add_argument("--root", required=True, help="staged tree to check")
    ap.add_argument("--report", help="write JSON link report here")
    ap.add_argument("--vendor-manifest", default="",
                    help="path to the extracted vendor .manifest (optional; feeds dlopen audit universe)")
    args = ap.parse_args()

    with open(args.manifest, encoding="utf-8") as fh:
        manifest = json.load(fh)
    pkg = next((p for p in manifest["packages"] if p["name"] == args.pkg), None)
    if pkg is None:
        print(f"package {args.pkg!r} not in manifest", file=sys.stderr)
        return 2

    files, links = load_staged_tree(args.root)
    c = Checker(manifest, args.root, files, links, vendor_manifest=args.vendor_manifest)
    c.run(pkg)

    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump({"package": args.pkg, "root": args.root,
                       "elf_dependencies": c.link_report}, fh, indent=2, sort_keys=True)

    for w in c.warnings:
        print(f"WARN {w}")
    if c.errors:
        for e in c.errors:
            print(f"FAIL {e}")
        print(f"linkcheck: {len(c.errors)} violation(s) in package {args.pkg}", file=sys.stderr)
        return 1
    n_elf = len(c.link_report)
    print(f"linkcheck: package {args.pkg} OK "
          f"({n_elf} ELF files closed, {len(links)} symlinks, "
          f"{len(files)} regular files under {args.root})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
