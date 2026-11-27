#!/usr/bin/env python3
"""Stage one package from an extracted NVIDIA vendor archive per the manifest.

Copies declared files (verifying any pinned hashes), creates declared symlinks,
records modes, and writes SHA256SUMS + build-info for the staged tree.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import sys


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--pkg", required=True)
    ap.add_argument("--files-dir", required=True, help="extracted vendor archive 'files' dir")
    ap.add_argument("--dest", required=True, help="staging destination root (must be empty or absent)")
    ap.add_argument("--build-info", default="", help="JSON dict embedded as .build-info in the tree")
    args = ap.parse_args()

    with open(args.manifest, encoding="utf-8") as fh:
        manifest = json.load(fh)
    pkg = next((p for p in manifest["packages"] if p["name"] == args.pkg), None)
    if pkg is None:
        print(f"unknown package {args.pkg!r}", file=sys.stderr)
        return 2

    if os.path.exists(args.dest) and os.listdir(args.dest):
        print(f"refusing to stage into non-empty {args.dest}", file=sys.stderr)
        return 2

    problems = []
    records = []

    for spec in pkg["files"]:
        src = os.path.join(args.files_dir, spec["archive"])
        if not os.path.isfile(src):
            problems.append(f"archive entry missing: {spec['archive']}")
            continue
        if re.match(r"^\./?32/", spec["archive"]) or spec["archive"].startswith("32/"):
            problems.append(f"32-bit entry must not be curated: {spec['archive']}")
            continue
        dst = os.path.join(args.dest, spec["install"])
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(src, dst)
        mode = int(spec.get("mode", "0644"), 8)
        os.chmod(dst, mode)
        digest = sha256_file(dst)
        pinned = spec.get("sha256")
        if pinned and digest != pinned:
            problems.append(
                f"hash mismatch for {spec['archive']}: staged {digest} != pinned {pinned}")
        records.append({"install": spec["install"], "archive": spec["archive"],
                        "sha256": digest, "size": os.path.getsize(dst),
                        "mode": spec.get("mode", "0644")})

    for spec in pkg.get("symlinks", []):
        link = os.path.join(args.dest, spec["install"])
        os.makedirs(os.path.dirname(link), exist_ok=True)
        if os.path.lexists(link):
            os.unlink(link)
        os.symlink(spec["target"], link)
        records.append({"install": spec["install"], "symlink_to": spec["target"]})

    with open(os.path.join(args.dest, "SHA256SUMS"), "w", encoding="utf-8") as fh:
        for r in sorted(records, key=lambda r: r["install"]):
            if "sha256" in r:
                fh.write(f"{r['sha256']}  {r['install']}\n")
            else:
                fh.write(f"# symlink {r['install']} -> {r['symlink_to']}\n")

    if args.build_info:
        info = json.loads(args.build_info)
    else:
        info = {}
    info.update({"package": pkg["name"], "version": pkg["version"],
                 "driver_version": manifest["driver_version"]})
    with open(os.path.join(args.dest, ".build-info"), "w", encoding="utf-8") as fh:
        json.dump(info, fh, indent=2, sort_keys=True)
        fh.write("\n")

    if problems:
        for p in problems:
            print(f"FAIL stage: {p}", file=sys.stderr)
        return 1
    print(f"staged {len(records)} entries for package {pkg['name']} into {args.dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
