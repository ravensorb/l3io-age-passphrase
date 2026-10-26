"""Streaming and one-shot passphrase encrypt/decrypt."""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import IO, cast

import pytest

import l3io_age_passphrase as age_pass

PLAIN = b"INSERT INTO t VALUES (1);\n" * 5000
PASSPHRASE = "test-passphrase-not-a-secret"
AGE_HEADER = b"age-encryption.org/v1"


class _ChunkedReader(io.RawIOBase):
    def __init__(self, data: bytes, chunk_size: int = 17) -> None:
        super().__init__()
        self._data = data
        self._chunk_size = chunk_size
        self._offset = 0

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if self._offset >= len(self._data):
            return b""
        if size is None or size < 0:
            size = self._chunk_size
        size = min(size, self._chunk_size, len(self._data) - self._offset)
        start = self._offset
        self._offset += size
        return self._data[start : self._offset]


def test_oneshot_round_trip() -> None:
    sealed = age_pass.encrypt(PLAIN, PASSPHRASE)
    assert sealed.startswith(AGE_HEADER)
    assert age_pass.decrypt(sealed, PASSPHRASE) == PLAIN


def test_io_round_trip() -> None:
    out = io.BytesIO()
    age_pass.encrypt_io(io.BytesIO(PLAIN), out, PASSPHRASE)
    data = out.getvalue()
    assert data.startswith(AGE_HEADER)
    plain = io.BytesIO()
    age_pass.decrypt_io(io.BytesIO(data), plain, PASSPHRASE)
    assert plain.getvalue() == PLAIN


def test_chunked_reader_streams() -> None:
    sealed = io.BytesIO()
    age_pass.encrypt_io(cast(IO[bytes], _ChunkedReader(PLAIN)), sealed, PASSPHRASE)
    plain = io.BytesIO()
    age_pass.decrypt_io(io.BytesIO(sealed.getvalue()), plain, PASSPHRASE)
    assert plain.getvalue() == PLAIN


def test_wrong_passphrase_raises() -> None:
    sealed = age_pass.encrypt(PLAIN, PASSPHRASE)
    with pytest.raises(age_pass.DecryptError):
        age_pass.decrypt(sealed, "wrong-passphrase")


def test_wrong_passphrase_io_raises() -> None:
    sealed = io.BytesIO()
    age_pass.encrypt_io(io.BytesIO(PLAIN), sealed, PASSPHRASE)
    with pytest.raises(age_pass.DecryptError):
        age_pass.decrypt_io(io.BytesIO(sealed.getvalue()), io.BytesIO(), "wrong")


def test_truncated_body_raises() -> None:
    sealed = age_pass.encrypt(PLAIN, PASSPHRASE)
    with pytest.raises(age_pass.DecryptError):
        age_pass.decrypt(sealed[: max(32, len(sealed) // 2)], PASSPHRASE)


def test_not_age_raises() -> None:
    with pytest.raises(age_pass.DecryptError):
        age_pass.decrypt(b"hello, not age", PASSPHRASE)


def test_armored_round_trip() -> None:
    sealed = age_pass.encrypt(PLAIN, PASSPHRASE, armored=True)
    assert sealed.startswith(b"-----BEGIN AGE ENCRYPTED FILE-----")
    assert age_pass.decrypt(sealed, PASSPHRASE) == PLAIN


def test_empty_plaintext() -> None:
    sealed = age_pass.encrypt(b"", PASSPHRASE)
    assert age_pass.decrypt(sealed, PASSPHRASE) == b""


def test_passphrase_never_in_exception_text() -> None:
    sealed = age_pass.encrypt(b"x", PASSPHRASE)
    with pytest.raises(age_pass.DecryptError) as info:
        age_pass.decrypt(sealed, "secret-that-must-not-leak")
    assert "secret-that-must-not-leak" not in str(info.value)
    assert PASSPHRASE not in str(info.value)


@pytest.mark.skipif(shutil.which("age") is None, reason="age CLI not installed")
def test_decrypts_with_stock_age() -> None:
    age_bin = shutil.which("age")
    assert age_bin is not None
    sealed = age_pass.encrypt(PLAIN, PASSPHRASE)
    with tempfile.TemporaryDirectory() as tempdir:
        enc = Path(tempdir) / "payload.age"
        out = Path(tempdir) / "payload.out"
        enc.write_bytes(sealed)
        import pty

        master, slave = pty.openpty()
        try:
            proc = subprocess.Popen(  # noqa: S603
                [age_bin, "--decrypt", "-o", str(out), str(enc)],
                stdin=slave,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
            )
            os.close(slave)
            slave = -1
            os.write(master, (PASSPHRASE + "\n").encode())
            stdout, stderr = proc.communicate(timeout=60)
        finally:
            os.close(master)
            if slave >= 0:
                os.close(slave)
        assert proc.returncode == 0, (stdout, stderr)
        assert out.read_bytes() == PLAIN


@pytest.mark.skipif(shutil.which("age") is None, reason="age CLI not installed")
def test_encrypt_with_stock_age_decrypts_here() -> None:
    """age -e -p (TTY) is awkward in CI; use batchpass when present."""
    age_bin = shutil.which("age")
    plugin = shutil.which("age-plugin-batchpass")
    if age_bin is None or plugin is None:
        pytest.skip("age + age-plugin-batchpass required")
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, (PASSPHRASE + "\n").encode())
    finally:
        os.close(write_fd)
    os.set_inheritable(read_fd, True)
    drop = {"AGE_PASSPHRASE", "AGE_PASSPHRASE_FILE"}
    env = {k: v for k, v in os.environ.items() if k not in drop}
    env["AGE_PASSPHRASE_FD"] = str(read_fd)
    try:
        proc = subprocess.Popen(  # noqa: S603
            [age_bin, "-e", "-j", "batchpass"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(read_fd,),
            env=env,
            close_fds=True,
        )
    finally:
        os.close(read_fd)
    assert proc.stdin is not None and proc.stdout is not None
    stdout, stderr = proc.communicate(PLAIN, timeout=60)
    assert proc.returncode == 0, stderr
    assert age_pass.decrypt(stdout, PASSPHRASE) == PLAIN
