# NVIDIA open: build the vendor payload

This recipe packages the x86-64 NVIDIA 620.70.06 vendor runtime and GA10x
firmware for the Workstation pilot. It copies the vendor binaries without
modifying them. It does not install a driver or affect Nouveau.

On Linux, use Bash, Python 3, GNU coreutils, GNU tar, gzip and `just`. Download
the `.run` from the URL in
[`nvidia-620.70.06.json`](manifests/nvidia-620.70.06.json) outside the
repository. From the repository root, pass the archive and an existing
scratch directory that you own, with mode `0700` and about 4 GiB free:

```sh
just build-nvidia /path/to/NVIDIA-Linux-x86_64-620.70.06.run /path/to/scratch
```

The command verifies the source pin before extraction and checks the staged
file hashes and ELF dependencies. It prints the private candidate directory
containing two tarballs, checksums and build reports. On normal exit or a
caught interruption it removes the work tree; after a crash, check that the
build has stopped before deleting stale scratch. The pinned extractor runs
as your user. In CI, run it in an isolated job without secrets.

The tarballs are intermediate inputs, not signed `systemd-sysupdate`
payloads. Follow the [candidate handoff](../../docs/candidate-handoff.md) for
module, notice and release requirements.

## Build unsigned open modules

The local module recipe targets the lab kernel `7.3.4-300.fc45.x86_64`.
Use an unprivileged x86-64 Fedora build environment with the kernel's
compatible GCC C and C++ compilers, binutils, Make, RPM tools, `cpio`, `tar`, `kmod`, and
the kernel build prerequisites. Use the pinned [upstream source archive]
and [Fedora kernel-devel RPM]. The recipe verifies both SHA-256 pins before
unpacking anything. Call it from the repository root:

```sh
just build-nvidia-modules /path/to/source.tar.gz /path/to/kernel-devel.rpm /path/to/scratch
```

The result is a private directory with the four unsigned pilot modules and
`SHA256SUMS`. The recipe checks the driver version, target kernel and absence
of a module signer. Do not install or publish this directory. This local
build is not a provenance attestation or a replacement for release signing.

[upstream source archive]: https://codeload.github.com/NVIDIA/open-gpu-kernel-modules/tar.gz/refs/tags/620.70.06
[Fedora kernel-devel RPM]: https://kojipkgs.fedoraproject.org/packages/kernel/7.3.4/300.fc45/data/signed/f577861e/x86_64/kernel-devel-7.3.4-300.fc45.x86_64.rpm
