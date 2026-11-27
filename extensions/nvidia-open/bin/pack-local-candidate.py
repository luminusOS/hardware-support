#!/usr/bin/env python3

import argparse
import hashlib
import io
import json
import os
import re
import signal
import stat
import tarfile
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from os import PathLike
from typing import BinaryIO

DOCUMENT_LIMIT = 16 * 1024
FILE_LIMIT = 128 << 20
ARCHIVE_LIMIT = 512 << 20
FILES = (
    "nvidia.ko",
    "nvidia-drm.ko",
    "nvidia-modeset.ko",
    "nvidia-uvm.ko",
    "nvidia-runtime-620.70.06.tar.gz",
    "nvidia-firmware-ga10x-620.70.06.tar.gz",
    "source-and-notices.tar.gz",
)
ENTRIES = ("candidate.json",) + FILES


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("duplicate manifest key")
    return value


class BoundedOutput:
    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream
        self.digest = hashlib.sha256()
        self.size = 0

    def write(self, data: bytes) -> int:
        self.size += len(data)
        if self.size > ARCHIVE_LIMIT:
            raise ValueError("archive exceeds 512 MiB transport limit")
        self.digest.update(data)
        return self.stream.write(data)

    def tell(self) -> int:
        return self.size

    def flush(self) -> None:
        self.stream.flush()


class CheckedInput:
    def __init__(self, fd: int, name: str, size: int, checkpoint: Callable[[], bool]) -> None:
        self.fd = fd
        self.name = name
        self.remaining = size
        self.digest = hashlib.sha256()
        self.checkpoint = checkpoint

    def read(self, amount: int = -1) -> bytes:
        if self.remaining == 0:
            return b""
        requested = min(amount if amount >= 0 else self.remaining, self.remaining)
        result = bytearray()
        while len(result) < requested:
            self.checkpoint()
            chunk = os.read(self.fd, requested - len(result))
            if not chunk:
                raise ValueError(f"candidate file shortened while packing: {self.name}")
            result.extend(chunk)
            self.remaining -= len(chunk)
            self.digest.update(chunk)
        return bytes(result)


def add_bytes(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    info.mode = 0o600
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.type = tarfile.REGTYPE
    archive.addfile(info, io.BytesIO(payload))


def reject_constant(value: str) -> None:
    raise ValueError(f"invalid non-finite JSON value: {value}")


@contextmanager
def cancellation_checkpoint(*, restore_handlers: bool) -> Iterator[Callable[[], bool]]:
    requested = None

    def record(signum: int, _frame: object) -> None:
        nonlocal requested
        if requested is None:
            requested = signum

    def checkpoint() -> bool:
        if (signum := requested) is not None:
            raise SystemExit(128 + signum)
        return True

    with ExitStack() as handlers:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous = signal.signal(signum, record)
            if restore_handlers:
                handlers.callback(signal.signal, signum, previous)
        yield checkpoint


def open_output_parent(path: str | PathLike[str]) -> tuple[int, str]:
    raw = os.fspath(path)
    if not isinstance(raw, str) or not raw or raw.endswith("/"):
        raise ValueError("output must name a file in a private parent directory")
    parent_name, basename = os.path.split(raw)
    if not basename or basename in (".", ".."):
        raise ValueError("output basename must not be empty, dot, or dot-dot")
    parent_fd = os.open(parent_name or ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    return parent_fd, basename


def pack(
    candidate: str | PathLike[str],
    output: str | PathLike[str],
    *,
    checkpoint: Callable[[], bool] = lambda: True,
) -> dict[str, int | str]:
    checkpoint()
    candidate_fd = None
    parent_fd = None
    output_fd = None
    output_name = ""
    complete = False
    try:
        candidate_fd = os.open(candidate, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_fd, output_name = open_output_parent(output)
        directory = os.fstat(candidate_fd)
        if directory.st_uid != os.geteuid() or stat.S_IMODE(directory.st_mode) != 0o700:
            raise ValueError("candidate must be an owned mode-0700 directory")
        parent = os.fstat(parent_fd)
        if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
            raise ValueError("output parent must be an owned mode-0700 directory")
        if (directory.st_dev, directory.st_ino) == (parent.st_dev, parent.st_ino):
            raise ValueError("output parent must differ from candidate directory")
        if set(os.listdir(candidate_fd)) != set(ENTRIES):
            raise ValueError("candidate must contain exactly the eight expected entries")
        manifest_fd = os.open("candidate.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                              dir_fd=candidate_fd)
        try:
            manifest_stat = os.fstat(manifest_fd)
            if not stat.S_ISREG(manifest_stat.st_mode) or manifest_stat.st_nlink != 1:
                raise ValueError("candidate manifest must be a regular unlinked file")
            if not 0 < manifest_stat.st_size <= DOCUMENT_LIMIT:
                raise ValueError("candidate manifest must be at most 16 KiB")
            manifest = b""
            while len(manifest) <= DOCUMENT_LIMIT:
                chunk = os.read(manifest_fd, DOCUMENT_LIMIT + 1 - len(manifest))
                if not chunk:
                    break
                manifest += chunk
            if len(manifest) != manifest_stat.st_size or len(manifest) > DOCUMENT_LIMIT:
                raise ValueError("candidate manifest changed or exceeded 16 KiB")
            after = os.fstat(manifest_fd)
            if (after.st_nlink != 1 or after.st_ino != manifest_stat.st_ino
                    or after.st_dev != manifest_stat.st_dev
                    or after.st_size != manifest_stat.st_size
                    or after.st_mtime_ns != manifest_stat.st_mtime_ns
                    or after.st_ctime_ns != manifest_stat.st_ctime_ns):
                raise ValueError("candidate manifest changed while reading")
        finally:
            os.close(manifest_fd)
        try:
            document = json.loads(manifest, object_pairs_hook=unique_object, parse_constant=reject_constant)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("invalid candidate manifest JSON") from error
        if (type(document) is not dict or set(document) != {"schema", "producer", "target", "files"}
                or type(document["schema"]) is not int or document["schema"] != 1
                or type(document["producer"]) is not dict or type(document["target"]) is not dict
                or type(document["files"]) is not dict or set(document["files"]) != set(FILES)):
            raise ValueError("invalid candidate manifest shape")
        for name, claim in document["files"].items():
            if (type(claim) is not dict or set(claim) != {"size", "sha256"}
                    or type(claim["size"]) is not int or not 0 < claim["size"] <= FILE_LIMIT
                    or type(claim["sha256"]) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", claim["sha256"], re.ASCII) is None):
                raise ValueError(f"invalid manifest file claim: {name}")
        checkpoint()
        output_fd = os.open(output_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600, dir_fd=parent_fd)
        checkpoint()
        output_stat = os.fstat(output_fd)
        if not stat.S_ISREG(output_stat.st_mode) or output_stat.st_nlink != 1:
            raise ValueError("created archive is not a private regular file")
        with os.fdopen(output_fd, "wb", closefd=False) as stream:
            bounded = BoundedOutput(stream)
            with tarfile.open(fileobj=bounded, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                add_bytes(archive, "candidate.json", manifest)
                for name in FILES:
                    checkpoint()
                    claim = document["files"][name]
                    try:
                        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                     dir_fd=candidate_fd)
                    except OSError as error:
                        raise ValueError(f"cannot safely open candidate entry: {name}") from error
                    try:
                        before = os.fstat(fd)
                        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                            raise ValueError(f"candidate entry must be a regular unlinked file: {name}")
                        if before.st_size != claim["size"]:
                            raise ValueError(f"candidate size does not match manifest: {name}")
                        source = CheckedInput(fd, name, before.st_size, checkpoint)
                        info = tarfile.TarInfo(name)
                        info.size = before.st_size
                        info.mode = 0o600
                        info.uid = info.gid = info.mtime = 0
                        info.uname = info.gname = ""
                        info.type = tarfile.REGTYPE
                        archive.addfile(info, source)
                        after = os.fstat(fd)
                        if (source.remaining or source.digest.hexdigest() != claim["sha256"]
                                or after.st_nlink != 1
                                or before.st_dev != after.st_dev or before.st_ino != after.st_ino
                                or before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns
                                or before.st_ctime_ns != after.st_ctime_ns):
                            raise ValueError(f"candidate bytes do not match stable manifest claim: {name}")
                    finally:
                        os.close(fd)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent_fd)
        result: dict[str, int | str] = {
            "archive_size": bounded.size,
            "archive_sha256": bounded.digest.hexdigest(),
            "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        }
        # This is the commit decision; a later signal must not hide a committed result.
        complete = checkpoint()
        return result
    finally:
        with ExitStack() as descriptors:
            if parent_fd is not None:
                descriptors.callback(os.close, parent_fd)
            if candidate_fd is not None:
                descriptors.callback(os.close, candidate_fd)
            if output_fd is not None:
                descriptors.callback(os.close, output_fd)
                if not complete and parent_fd is not None:
                    try:
                        os.unlink(output_name, dir_fd=parent_fd)
                        os.fsync(parent_fd)
                    except FileNotFoundError:
                        pass


def main(*, standalone: bool = False) -> None:
    parser = argparse.ArgumentParser(description="Pack a local unsigned NVIDIA candidate")
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    with cancellation_checkpoint(restore_handlers=not standalone) as checkpoint:
        try:
            result = pack(args.candidate, args.output, checkpoint=checkpoint)
            print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        else:
            if standalone:
                # CPython resets custom signal handlers during finalization but preserves SIG_IGN.
                for signum in (signal.SIGINT, signal.SIGTERM):
                    signal.signal(signum, signal.SIG_IGN)


if __name__ == "__main__":
    main(standalone=True)
