#!/usr/bin/env bash
set -euo pipefail
umask 077

die() { printf '%s\n' "$*" >&2; exit 1; }

[[ $# -eq 3 ]] || die "Usage: bash $0 OPEN_SOURCE_ARCHIVE KERNEL_DEVEL_RPM SCRATCH_DIRECTORY"
[[ $EUID -ne 0 && $(uname -m) == x86_64 ]] ||
    die "Build as an unprivileged user on x86_64"
[[ -f $1 && -f $2 ]] || die "Expected existing source and kernel-devel files"
if ! scratch=$(realpath -e -- "$3") ||
    [[ ! -d $scratch || ! -O $scratch || $(stat -c '%a' -- "$scratch") != 700 ]]; then
    die "scratch must be an owned directory with mode 0700"
fi

version=620.70.06
kernel=7.3.4-300.fc45.x86_64
source_sha=bc9fa156dcdc5e0ed19c3c9ea70cfe2b8c9a0fdc415426af1ba5c3a1f9a7238d
rpm_sha=15fee909a66e996421444d42fff9a1a1555fc6689abdb45f01fe72d65dc8f59e
job=$(mktemp -d -- "$scratch/nvidia-modules.XXXXXXXX")
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
mkdir -- "$work"
cp -- "$1" "$work/source.tar.gz"
cp -- "$2" "$work/kernel-devel.rpm"
cd -- "$work"
printf '%s  source.tar.gz\n' "$source_sha" | sha256sum --status -c - ||
    die "source SHA-256 mismatch"
printf '%s  kernel-devel.rpm\n' "$rpm_sha" | sha256sum --status -c - ||
    die "kernel-devel SHA-256 mismatch"
for tool in gcc g++ make rpm2cpio cpio tar modinfo; do
    command -v "$tool" >/dev/null || die "Missing module build tool: $tool"
done

rpm2cpio kernel-devel.rpm | cpio -idmu --quiet
tar -xf source.tar.gz
source_dir="$work/open-gpu-kernel-modules-$version"
kernel_dir="$work/usr/src/kernels/$kernel"
[[ -f $kernel_dir/Module.symvers && -f $source_dir/Makefile ]] ||
    die "Pinned inputs did not provide the expected build tree"
make -C "$source_dir" -j6 modules SYSSRC="$kernel_dir" SYSOUT="$kernel_dir" >&2

mkdir -- "$work/unsigned"
modules=(nvidia.ko nvidia-modeset.ko nvidia-drm.ko nvidia-uvm.ko)
for module in "${modules[@]}"; do
    path="$source_dir/kernel-open/$module"
    [[ -f $path && ! -L $path ]] || die "Missing regular module: $module"
    vermagic=$(modinfo -F vermagic "$path")
    module_version=$(modinfo -F version "$path")
    signer=$(modinfo -F signer "$path")
    [[ ${vermagic%% *} == "$kernel" && $module_version == "$version" && -z $signer ]] ||
        die "Unexpected version, kernel or signer: $module"
    install -m 0644 -- "$path" "$work/unsigned/$module"
done
(
    cd -- "$work/unsigned"
    sha256sum "${modules[@]}" > SHA256SUMS
)
mv -- "$work/unsigned" "$job/candidate"
complete=1
printf '%s\n' "$job/candidate"
