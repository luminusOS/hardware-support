# Candidate handoff to `images`

The local NVIDIA command is a producer step, not an admission or release
interface. Its checksums detect corruption; they do not authenticate the
producer. The following requirements apply before connecting a hosted
producer to `images`.

1. **Freeze the target.** `images` supplies the target image build, OCI
   platform manifest digest, architecture, kernel release and verified
   `kernel-devel` identity from the frozen candidate. A moving tag, the
   runner's active kernel, or just the NVIDIA driver version is not a target
   identity.
2. **Build and record.** `hardware-support` records the exact producer repo,
   commit, workflow/run/attempt, input pins and artifact digests. For NVIDIA,
   build unsigned open modules against the supplied kernel and keep those
   separate from the byte-pinned userspace and GA10x blobs. Include the
   matching source and original notices for the final companion.
3. **Admit privately.** `images` verifies the approved producer workflow and
   run identity from trusted provenance independent of the candidate
   metadata. It checks exact file names, sizes, hashes and target identity.
   Mismatches or missing provenance are refusals. Do not pass production
   signing or publication credentials to the build repository.
4. **Sign and assemble.** The protected release path checks module metadata,
   signs modules under separate module trust, assembles the passive
   `early.cpio.gz` and target-labelled `runtime.raw`, and binds them to the
   target in the signed manifest. The release supplies source and notices
   outside the passive archive. Only `images` can authorize publication, after
   the existing validation and manual approval gates.

The MacBook Bluetooth recipe is future work. It can use this provenance and
admission boundary without adopting the NVIDIA early-boot archive.
