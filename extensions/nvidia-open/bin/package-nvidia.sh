#!/usr/bin/env bash
# PILOT NVIDIA runtime + GA10x firmware packager (no installation, host unchanged).
#
# Flow: verify pinned .run SHA -> extract-only -> assert version pairing and
# firmware paths from archive sources -> stage curated trees -> linkcheck ->
# reproducible tarballs into OUT. Writes only under WORK/OUT (default
# /tmp/opencode/...); refuses other locations unless --allow-any-workdir.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${HERE}/../manifests/nvidia-620.70.06.json"
WORK="/tmp/opencode/nvidia-packaging"
OUT=""
RUN_CACHE="${NVIDIA_RUN_CACHE:-}"
EXTRACT_TIMEOUT="${EXTRACT_TIMEOUT:-420}"
ALLOW_ANY_WORKDIR=0
SKIP_DOWNLOAD="${SKIP_DOWNLOAD:-0}"

die() { echo "ERROR: $*" >&2; exit 1; }
step() { echo "=== $* ==="; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest) MANIFEST="$2"; shift 2 ;;
    --workdir)  WORK="$2"; shift 2 ;;
    --out)      OUT="$2"; shift 2 ;;
    --run-cache) RUN_CACHE="$2"; shift 2 ;;
    --allow-any-workdir) ALLOW_ANY_WORKDIR=1; shift ;;
    *) die "unknown option: $1" ;;
  esac
done
OUT="${OUT:-${WORK}/out}"

for d in "$WORK" "$OUT"; do
  if [[ $ALLOW_ANY_WORKDIR -eq 0 && "$d" != /tmp/opencode/* ]]; then
    die "refusing to write outside /tmp/opencode: $d (this pilot must not touch the host); pass --allow-any-workdir deliberately"
  fi
done

command -v sha256sum >/dev/null || die "sha256sum missing"
command -v python3 >/dev/null || die "python3 missing"
tar --version | grep -qi 'GNU tar' || die "GNU tar required for deterministic --sort/--mtime"

PY="${PYTHON:-python3}"
VERSION="$("$PY" -c 'import json,sys;print(json.load(open(sys.argv[1]))["driver_version"])' "$MANIFEST")"
URL="$("$PY" -c 'import json,sys;print(json.load(open(sys.argv[1]))["vendor_archive"]["url"])' "$MANIFEST")"
PIN_SHA="$("$PY" -c 'import json,sys;print(json.load(open(sys.argv[1]))["vendor_archive"]["sha256"])' "$MANIFEST")"
LICENSE_SHA="$("$PY" -c 'import json,sys;print(json.load(open(sys.argv[1]))["vendor_archive"]["license_sha256"])' "$MANIFEST")"
SIZE="$("$PY" -c 'import json,sys;print(json.load(open(sys.argv[1]))["vendor_archive"]["size_bytes"])' "$MANIFEST")"
MTIME_EPOCH="$("$PY" -c 'import json,sys;print(json.load(open(sys.argv[1]))["reproducible_tar"]["mtime_epoch"])' "$MANIFEST")"

mkdir -p "$WORK/vendor" "$OUT"
RUN="${WORK}/vendor/NVIDIA-Linux-x86_64-${VERSION}.run"
FILES_DIR="${WORK}/vendor/files"
EXTRACT_DIRTY="${WORK}/vendor/.extracted-from"

step "1/6 verify vendor archive before extraction"
if [[ ! -f "$RUN" ]]; then
  if [[ -n "$RUN_CACHE" && -f "$RUN_CACHE" ]]; then
    cp -a "$RUN_CACHE" "$RUN"
  elif [[ $SKIP_DOWNLOAD -eq 1 ]]; then
    die "no cached .run at $RUN and SKIP_DOWNLOAD=1"
  else
    [[ -n "$RUN_CACHE" ]] && cp -a "$RUN_CACHE" "$RUN" || {
      command -v curl >/dev/null || die "curl missing and no archive cache"
      echo "downloading $URL"
      curl -fsSL --retry 3 -o "$RUN" "$URL"
    }
  fi
fi
printf '%s\n' "${PIN_SHA}  ${RUN}" | sha256sum --status -c - ||
  die "SHA-256 mismatch for vendor archive — refusing to extract"
[[ "$(stat -c %s "$RUN")" == "$SIZE" ]] || die "vendor archive size mismatch"
echo "pinned SHA verified for $(basename "$RUN") (${SIZE} bytes)"

step "2/6 extract-only, always fresh (never --install, never as root)"
# A cached extraction cannot authenticate files replaced after the fact, so the
# tree is always rebuilt from the just-verified archive. EXTRACT_DIRTY records
# the archive hash that produced the current files/ for audit only.
rm -f "$EXTRACT_DIRTY"
rm -rf "$FILES_DIR"
( cd "$WORK/vendor" && timeout "$EXTRACT_TIMEOUT" sh "$RUN" --extract-only --target files >/dev/null )
echo "$PIN_SHA" > "$EXTRACT_DIRTY"

step "3/6 version pairing + firmware path assertions from archive sources"
# NV_VERSION_STRING is injected at module compile time (Kbuild), not a header.
grep -qF -- "-DNV_VERSION_STRING=\\\"${VERSION}\\\"" "$FILES_DIR/kernel-open/Kbuild" ||
  die "kernel-open/Kbuild does not pin NV_VERSION_STRING to ${VERSION}"
[[ "$("$PY" -c 'import sys;print(open(sys.argv[1],encoding="utf-8",errors="replace").read().splitlines()[1].strip())' "$FILES_DIR/.manifest")" == "$VERSION" ]] ||
  die "vendor .manifest version line != ${VERSION}"
grep -q '#define NV_FIRMWARE_FOR_NAME(name)  "nvidia/" NV_VERSION_STRING "/" name ".bin"' \
  "$FILES_DIR/kernel-open/nvidia/nv.c" || die "firmware path rule changed in nv.c"
for f in gsp_ga10x ucodes_ga10x; do
  grep -q "NV_FIRMWARE_DECLARE_GSP(\"${f}\")" \
    "$FILES_DIR/kernel-open/common/inc/nv-firmware.h" ||
    die "module does not declare ${f} in this archive"
done
grep -q 'NV_FIRMWARE_CHIP_FAMILY_GA10X: return "ga10x"' \
  "$FILES_DIR/kernel-open/common/inc/nv-firmware.h" || die "GA10X family mapping changed"
printf '%s\n' "${LICENSE_SHA}  LICENSE" | ( cd "$FILES_DIR" && sha256sum --status -c - ) ||
  die "vendor LICENSE hash mismatch (redistribution terms may differ from manifest notes)"

step "4/6 stage curated trees"
rm -rf "${WORK}/stage"
rm -f "${OUT}"/nvidia-runtime-*.tar.gz "${OUT}"/nvidia-firmware-*.tar.gz \
      "${OUT}/SHA256SUMS" "${OUT}/build-report.json" "${OUT}/linkcheck-runtime.json"
MANIFEST_SHA="$("$PY" -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$MANIFEST")"
"$PY" "${HERE}/stage.py" --manifest "$MANIFEST" --pkg nvidia-runtime \
  --files-dir "$FILES_DIR" --dest "${WORK}/stage/nvidia-runtime-${VERSION}" \
  --build-info "{\"vendor_archive_sha256\":\"${PIN_SHA}\",\"manifest_sha256\":\"${MANIFEST_SHA}\",\"tool\":\"package-nvidia.sh\"}"
"$PY" "${HERE}/stage.py" --manifest "$MANIFEST" --pkg nvidia-firmware-ga10x \
  --files-dir "$FILES_DIR" --dest "${WORK}/stage/nvidia-firmware-ga10x-${VERSION}" \
  --build-info "{\"vendor_archive_sha256\":\"${PIN_SHA}\",\"tool\":\"package-nvidia.sh\"}"

step "5/6 link-safe + registration + audit checks"
"$PY" "${HERE}/linkcheck.py" --manifest "$MANIFEST" --pkg nvidia-runtime \
  --root "${WORK}/stage/nvidia-runtime-${VERSION}" \
  --vendor-manifest "${FILES_DIR}/.manifest" \
  --report "${WORK}/out/linkcheck-runtime.json"
"$PY" "${HERE}/linkcheck.py" --manifest "$MANIFEST" --pkg nvidia-firmware-ga10x \
  --root "${WORK}/stage/nvidia-firmware-ga10x-${VERSION}"

step "6/6 reproducible tarballs"
for pkgdir in "${WORK}/stage/"*; do
  name="$(basename "$pkgdir")"
  tarball="${OUT}/${name}.tar.gz"
  tar --format=gnu --sort=name --owner=0 --group=0 --numeric-owner \
      --mtime="@${MTIME_EPOCH}" \
      -C "$(dirname "$pkgdir")" -cf - "$name" | gzip -n -9 > "$tarball"
done
( cd "$OUT" && sha256sum *.tar.gz > SHA256SUMS )
find "$OUT" -maxdepth 1 -name '*.tar.gz' -printf '%f %s bytes\n' | sort
"$PY" - "$OUT" "${WORK}/stage" <<'EOF'
import hashlib, json, os, subprocess, sys
out, stage = sys.argv[1], sys.argv[2]
listing = {}
for d in sorted(os.listdir(stage)):
    tgz = os.path.join(out, d + ".tar.gz")
    with subprocess.Popen(["tar", "-tzf", tgz], stdout=subprocess.PIPE) as p:
        names = sorted(p.stdout.read().decode().splitlines())
    listing[d] = {"sha256": hashlib.sha256(open(tgz, "rb").read()).hexdigest(),
                  "entries": len(names)}
json.dump(listing, open(os.path.join(out, "build-report.json"), "w"), indent=2, sort_keys=True)
print(json.dumps(listing, indent=2, sort_keys=True))
EOF

echo "PACKAGING_OK"
