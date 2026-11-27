#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import re
import secrets
import signal
import stat
from collections.abc import Callable, Iterator, Sequence
from contextlib import ExitStack, contextmanager
from pathlib import Path

DOCUMENT_LIMIT = 16 * 1024
FILE_LIMIT = 128 << 20
MODULES = ("nvidia.ko", "nvidia-drm.ko", "nvidia-modeset.ko", "nvidia-uvm.ko")
FILES = MODULES + (
    "nvidia-runtime-620.70.06.tar.gz",
    "nvidia-firmware-ga10x-620.70.06.tar.gz",
    "source-and-notices.tar.gz",
)
PRODUCER = {
    "repository": r"[\w.-]+/[\w.-]+",
    "commit": r"[0-9a-f]{40}",
    "workflow": r"\.github/workflows/[\w.-]+\.ya?ml",
    "run_id": None,
    "attempt": None,
}
TARGET = {
    "version": r"[0-9]+\.[0-9]{8}\.[0-9]+",
    "manifest": r"sha256:[0-9a-f]{64}",
    "architecture": r"[a-z0-9_]+",
    "kernel": r"[A-Za-z0-9][A-Za-z0-9._+-]*",
    "kernel_devel_sha256": r"[0-9a-f]{64}",
}


def validate_identity(value: dict[str, object], fields: dict[str, str | None]) -> None:
    if type(value) is not dict or value.keys() != fields.keys():
        raise ValueError("invalid producer or target identity fields")
    for name, pattern in fields.items():
        item = value[name]
        valid = (type(item) is int and item > 0) if pattern is None else (
            type(item) is str and re.fullmatch(pattern, item, re.ASCII)
        )
        if not valid:
            raise ValueError(f"invalid identity field: {name}")


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate JSON key")
    return result


def load_identity(value: str) -> object:
    if len(value.encode("utf-8")) > DOCUMENT_LIMIT:
        raise ValueError("identity JSON exceeds 16 KiB")
    return json.loads(value, object_pairs_hook=unique_object)


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


def cleanup_candidate(parent_fd: int, name: str, candidate_fd: int | None) -> None:
    if candidate_fd is not None:
        for file_name in FILES + ("candidate.json",):
            try:
                os.unlink(file_name, dir_fd=candidate_fd)
            except FileNotFoundError:
                pass
    os.rmdir(name, dir_fd=parent_fd)


def assemble(
    output: str,
    producer: dict[str, object],
    target: dict[str, object],
    file_arguments: Sequence[str],
    *,
    checkpoint: Callable[[], bool] = lambda: True,
) -> Path:
    checkpoint()
    validate_identity(producer, PRODUCER)
    validate_identity(target, TARGET)
    if target["architecture"] != "x86_64":
        raise ValueError("unsupported local candidate target")
    supplied = {}
    for argument in file_arguments:
        if "=" not in argument:
            raise ValueError("files must use NAME=PATH")
        name, path = argument.split("=", 1)
        if name not in FILES or name in supplied or not path:
            raise ValueError("unexpected or duplicate input file")
        supplied[name] = Path(path)
    if supplied.keys() != set(FILES):
        raise ValueError("exactly the seven named input files are required")
    candidate_name = "local-candidate-" + secrets.token_hex(8)
    output_fd = None
    candidate_fd = None
    created = False
    complete = False
    try:
        try:
            output_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as error:
            raise ValueError("output must be a real owned directory with mode 0700") from error
        info = os.fstat(output_fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("output must be an owned directory with mode 0700")
        os.mkdir(candidate_name, 0o700, dir_fd=output_fd)
        created = True
        candidate_fd = os.open(candidate_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=output_fd)
        claims = {}
        for name in FILES:
            checkpoint()
            source = supplied[name]
            try:
                source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except OSError as error:
                raise ValueError(f"cannot safely open input: {name}") from error
            dest_fd = None
            try:
                digest = hashlib.sha256()
                size = 0
                before = os.fstat(source_fd)
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                    raise ValueError(f"input must be a regular non-linked file: {name}")
                if not 0 < before.st_size <= FILE_LIMIT:
                    raise ValueError(f"invalid input size: {name}")
                dest_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                  0o600, dir_fd=candidate_fd)
                while chunk := os.read(source_fd, 1024 * 1024):
                    checkpoint()
                    size += len(chunk)
                    if size > FILE_LIMIT:
                        raise ValueError(f"input grew beyond size limit: {name}")
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        view = view[os.write(dest_fd, view):]
                after = os.fstat(source_fd)
                if (not stat.S_ISREG(after.st_mode) or after.st_nlink != 1
                        or size != before.st_size or before.st_dev != after.st_dev
                        or before.st_ino != after.st_ino or before.st_size != after.st_size
                        or before.st_mtime_ns != after.st_mtime_ns
                        or before.st_ctime_ns != after.st_ctime_ns):
                    raise ValueError(f"input changed while copying: {name}")
                os.fsync(dest_fd)
            finally:
                with ExitStack() as descriptors:
                    descriptors.callback(os.close, source_fd)
                    if dest_fd is not None:
                        descriptors.callback(os.close, dest_fd)
            claims[name] = {"size": size, "sha256": digest.hexdigest()}
        document = {
            "schema": 1,
            "producer": producer,
            "target": target,
            "files": claims,
        }
        payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(payload) > DOCUMENT_LIMIT:
            raise ValueError("candidate manifest exceeds 16 KiB")
        manifest_fd = os.open("candidate.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                              0o600, dir_fd=candidate_fd)
        try:
            remaining = memoryview(payload)
            while remaining:
                remaining = remaining[os.write(manifest_fd, remaining):]
            os.fsync(manifest_fd)
        finally:
            os.close(manifest_fd)
        os.fsync(candidate_fd)
        result = Path(output) / candidate_name
        # This is the commit decision; a later signal must not hide a committed result.
        complete = checkpoint()
        return result
    finally:
        with ExitStack() as descriptors:
            if output_fd is not None:
                descriptors.callback(os.close, output_fd)
            if candidate_fd is not None:
                descriptors.callback(os.close, candidate_fd)
            if not complete and created and output_fd is not None:
                cleanup_candidate(output_fd, candidate_name, candidate_fd)


def main(*, standalone: bool = False) -> None:
    parser = argparse.ArgumentParser(description="Assemble an unsigned local NVIDIA candidate")
    parser.add_argument("--output", required=True)
    parser.add_argument("--producer", required=True, type=load_identity)
    parser.add_argument("--target", required=True, type=load_identity)
    parser.add_argument("--file", action="append", default=[])
    args = parser.parse_args()
    with cancellation_checkpoint(restore_handlers=not standalone) as checkpoint:
        try:
            result = assemble(args.output, args.producer, args.target, args.file,
                              checkpoint=checkpoint)
            print(result, flush=True)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        else:
            if standalone:
                # CPython resets custom signal handlers during finalization but preserves SIG_IGN.
                for signum in (signal.SIGINT, signal.SIGTERM):
                    signal.signal(signum, signal.SIG_IGN)


if __name__ == "__main__":
    main(standalone=True)
