# LuminusOS hardware support

This repository produces optional hardware payloads for LuminusOS. It does not
build the Workstation OCI image, install anything on the host, or publish a
`testing` or `stable` release. See the [candidate handoff](docs/candidate-handoff.md)
for the responsibilities of this repository and `images`.

## NVIDIA open: first producer

The current recipe in `extensions/nvidia-open/` implements the x86-64 NVIDIA
620.70.06 vendor-payload stage: a curated GLVND/PRIME runtime and two GA10x
firmware blobs for the pilot. It reuses the tested LuminusOS packaging recipe.
The NVIDIA binaries and firmware are copied unmodified; the recipe does not
install the NVIDIA driver or add a global Nouveau blacklist.

Check the recipe with `just check` and `just test`. To build, use an
unprivileged Linux environment with Bash, Python 3, GNU coreutils, GNU tar,
gzip and `just`. Download the `.run` from the URL in
[`nvidia-620.70.06.json`](extensions/nvidia-open/manifests/nvidia-620.70.06.json)
and save it outside the repository. Pass the archive and an existing scratch
directory that you own, with mode `0700` and about 4 GiB free:

```sh
just build-nvidia /path/to/NVIDIA-Linux-x86_64-620.70.06.run /path/to/scratch
```

The command prints a fresh candidate directory. It checks the archive pin
before extraction, checks per-file pins and ELF dependencies, and removes the
working tree on normal exit or a caught interruption. After a crash, remove
stale scratch only after confirming the build has stopped. The NVIDIA
extractor runs as your user; CI should run it in an isolated job without
secrets. The candidate directory contains two tarballs, checksums and build
reports. Keep that output private. These tarballs are inputs to later
assembly; they are not signed `systemd-sysupdate` payloads. The open-module
build, source/notice delivery and hosted handoff are not wired yet.
