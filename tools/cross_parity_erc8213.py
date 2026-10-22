#!/usr/bin/env python3
"""Cross-implementation parity gate for PQ1's ERC-8213 fingerprints.

The Rust leg executes the production ``pqsigner-tx-core`` functions through a
small root-lockfile example.  This coordinator recomputes the same fixed boundary
vectors with pycryptodome-backed ``eth-hash`` from the lock-pinned official
ERC-7730 tool environment.  Missing dependencies, partial runner output, extra
vectors, and any byte mismatch are hard failures.

Run via ``make erc7730-cross-parity`` so the Python environment is locked.
"""

from __future__ import annotations

import importlib.metadata
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from eth_hash.auto import keccak


OFFICIAL_TOOL_VERSION = "1.0.9"
PROTOCOL = "pq1-erc8213-parity-v1"
ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class CalldataVector:
    name: str
    data: bytes
    digest: bytes


@dataclass(frozen=True)
class Eip712Vector:
    name: str
    domain_separator: bytes
    struct_hash: bytes
    digest: bytes


def installed_tool_version() -> str:
    try:
        return importlib.metadata.version("erc7730")
    except importlib.metadata.PackageNotFoundError as error:
        raise RuntimeError(
            "lock-pinned erc7730 environment is missing; run via "
            "`make erc7730-cross-parity`"
        ) from error


def expected_calldata() -> dict[str, bytes]:
    transfer = bytes.fromhex(
        "a9059cbb"
        + "00" * 12
        + "11223344556677889900aabbccddeeff00112233"
        + "00" * 31
        + "2a"
    )
    return {
        "empty": b"",
        "single-zero": b"\x00",
        "three-bytes": bytes.fromhex("abcdef"),
        "erc20-transfer": transfer,
        "max-4kib-pattern": bytes((index * 29 + 7) & 0xFF for index in range(4096)),
        # MAX_TX_LEN since 2026-10-22.
        "max-8kib-pattern": bytes((index * 29 + 7) & 0xFF for index in range(8192)),
    }


def expected_eip712() -> dict[str, tuple[bytes, bytes]]:
    return {
        "all-zero": (bytes(32), bytes(32)),
        "uniform": (bytes([0x11]) * 32, bytes([0x22]) * 32),
        "asymmetric-pattern": (
            bytes((index * 3 + 1) & 0xFF for index in range(32)),
            bytes((255 - index * 5) & 0xFF for index in range(32)),
        ),
    }


def _decode_hex(text: str, *, width: int | None = None) -> bytes:
    if text.startswith("0x") or len(text) % 2:
        raise ValueError(f"non-canonical hex: {text!r}")
    try:
        decoded = bytes.fromhex(text)
    except ValueError as error:
        raise ValueError(f"invalid hex: {text!r}") from error
    if decoded.hex() != text:
        raise ValueError(f"hex must be lowercase: {text!r}")
    if width is not None and len(decoded) != width:
        raise ValueError(f"expected {width} bytes, got {len(decoded)}")
    return decoded


def parse_runner_output(output: str) -> tuple[list[CalldataVector], list[Eip712Vector]]:
    lines = output.splitlines()
    if not lines or lines[0] != PROTOCOL:
        raise ValueError("runner protocol header missing or wrong")

    calldata: list[CalldataVector] = []
    eip712: list[Eip712Vector] = []
    seen: set[tuple[str, str]] = set()
    for line_number, line in enumerate(lines[1:], start=2):
        columns = line.split("\t")
        if not columns or columns[0] not in {"calldata", "eip712"}:
            raise ValueError(f"line {line_number}: unknown record")
        if len(columns) not in {4, 5}:
            raise ValueError(f"line {line_number}: wrong column count")
        kind, name = columns[0], columns[1]
        if not name or (kind, name) in seen:
            raise ValueError(f"line {line_number}: empty or duplicate name")
        seen.add((kind, name))
        if kind == "calldata":
            if len(columns) != 4:
                raise ValueError(f"line {line_number}: calldata column count")
            calldata.append(
                CalldataVector(name, _decode_hex(columns[2]), _decode_hex(columns[3], width=32))
            )
        else:
            if len(columns) != 5:
                raise ValueError(f"line {line_number}: EIP-712 column count")
            eip712.append(
                Eip712Vector(
                    name,
                    _decode_hex(columns[2], width=32),
                    _decode_hex(columns[3], width=32),
                    _decode_hex(columns[4], width=32),
                )
            )
    return calldata, eip712


def verify_vectors(calldata: list[CalldataVector], eip712: list[Eip712Vector]) -> int:
    expected_cd = expected_calldata()
    expected_712 = expected_eip712()
    if {vector.name for vector in calldata} != set(expected_cd):
        raise ValueError("calldata vector set is incomplete or contains extras")
    if {vector.name for vector in eip712} != set(expected_712):
        raise ValueError("EIP-712 vector set is incomplete or contains extras")

    checked = 0
    for vector in calldata:
        if vector.data != expected_cd[vector.name]:
            raise ValueError(f"runner changed calldata fixture {vector.name!r}")
        reference = keccak(len(vector.data).to_bytes(32, "big") + vector.data)
        if vector.digest != reference:
            raise ValueError(
                f"calldata digest mismatch for {vector.name}: "
                f"rust={vector.digest.hex()} reference={reference.hex()}"
            )
        checked += 1

    for vector in eip712:
        domain_separator, struct_hash = expected_712[vector.name]
        if (vector.domain_separator, vector.struct_hash) != (domain_separator, struct_hash):
            raise ValueError(f"runner changed EIP-712 fixture {vector.name!r}")
        reference = keccak(b"\x19\x01" + domain_separator + struct_hash)
        if vector.digest != reference:
            raise ValueError(
                f"EIP-712 digest mismatch for {vector.name}: "
                f"rust={vector.digest.hex()} reference={reference.hex()}"
            )
        checked += 1
    return checked


def main() -> int:
    if installed_tool_version() != OFFICIAL_TOOL_VERSION:
        raise RuntimeError(
            f"erc7730 package must be exactly {OFFICIAL_TOOL_VERSION}; "
            "run via `make erc7730-cross-parity`"
        )
    # Pin the oracle to Keccak-256 rather than standardized SHA3-256.
    if keccak(b"").hex() != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470":
        raise RuntimeError("independent Keccak oracle failed its canonical empty-input KAT")

    result = subprocess.run(
        [
            "cargo",
            "run",
            "--locked",
            "--quiet",
            "-p",
            "pqsigner-tx-core",
            "--example",
            "erc8213_vectors",
        ],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
        raise RuntimeError(f"Rust parity runner failed: {detail}")
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    calldata, eip712 = parse_runner_output(result.stdout)
    checked = verify_vectors(calldata, eip712)
    print(
        f"ERC-8213 cross parity: PASS ({checked} vectors; "
        f"pqsigner-tx-core vs eth-hash/pycryptodome)"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"ERC-8213 cross parity: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
