#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 2 ]]; then
    printf 'Usage: bash %s VENDOR_ARCHIVE SCRATCH_DIRECTORY\n' "$0" >&2
    exit 2
fi
if [[ $EUID -eq 0 ]]; then
    printf 'Run the NVIDIA producer as an unprivileged user\n' >&2
    exit 2
fi
if [[ ! -f $1 ]]; then
    printf 'expected an existing vendor archive\n' >&2
    exit 2
fi
archive=$(realpath -e -- "$1")
if ! scratch=$(realpath -e -- "$2") ||
    [[ ! -d $scratch || ! -O $scratch || $(stat -c '%a' -- "$scratch") != 700 ]]; then
    printf 'scratch must be an owned directory with mode 0700\n' >&2
    exit 2
fi
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

job=$(mktemp -d -- "$scratch/nvidia-open.XXXXXXXX")
complete=0
cleanup() {
    if (( complete )); then
        rm -rf -- "$job/work"
    else
        rm -rf -- "$job"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

work="$job/work"
SKIP_DOWNLOAD=1 bash "$here/package-nvidia.sh" \
    --allow-any-workdir --workdir "$work" --run-cache "$archive" >&2
(
    cd -- "$work/out"
    sha256sum -c SHA256SUMS
) >&2
mv -- "$work/out" "$job/candidate"
complete=1
printf '%s\n' "$job/candidate"
