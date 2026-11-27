<div align="center">
  <img src="https://raw.githubusercontent.com/luminusOS/images/0029ba9ddebb0a81d4c18be383efcbbd6d9b6f92/editions/workstation/files/system/usr/share/icons/hicolor/scalable/apps/luminusos-logo-icon.svg" alt="" width="80">

# LuminusOS Hardware Support

Recipes and validation for optional Workstation hardware extensions.

[Browse recipes](extensions/) · [Run the checks](#run-the-checks) · [Candidate handoff](docs/candidate-handoff.md)

</div>

Use this repository to develop and test optional hardware support for
LuminusOS Workstation. The recipes let you prepare drivers and firmware
without rebuilding the base image or installing them on your host.

## Run the checks

On Linux, install Git, Bash, Python 3, GNU coreutils, and
[`just`](https://github.com/casey/just). Then clone the repository and run the
checks:

```sh
git clone https://github.com/luminusOS/hardware-support.git
cd hardware-support
just check
just test
```

`just check` checks the shell scripts for syntax errors. `just test` runs the
recipe tests. Neither requires vendor downloads, root access, or a matching
device.

## Build a candidate

Browse [`extensions/`](extensions/) for recipe scripts and pinned input
manifests. Run `just --list` from the repository root to see the available
build commands and the arguments they take. Review the recipe's input
manifest before supplying your own inputs.

> [!IMPORTANT]
> This is a public source repository. Keep candidate binaries and build
> credentials out of Git history, releases, and public Actions artifacts.
> A local candidate is not an installable LuminusOS update.

## Build and release responsibilities

`hardware-support` defines the recipes and produces candidates.
[`images`](https://github.com/luminusOS/images) owns the Workstation image,
verifies candidates against the target deployment, and handles signing,
boot integration, and publication. See the
[candidate handoff](docs/candidate-handoff.md) for what each repository
must verify.
