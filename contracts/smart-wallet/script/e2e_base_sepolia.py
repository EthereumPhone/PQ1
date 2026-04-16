#!/usr/bin/env python3
"""
E2E test on Base Sepolia: sign a UserOp that sends 0 ETH to itself.

Steps:
1. Build the UserOp struct
2. Compute userOpHash (EntryPoint v0.6 style)
3. Sign with main key using SPHINCS+C7
4. ABI-encode PQSignatureWrapper
5. Output the handleOps calldata for cast send
"""
import sys, os, json, struct
from Crypto.Hash import keccak as _keccak_mod

sys.path.insert(0, os.path.dirname(__file__))
from signer_c7 import (
    sign_with_known_keys, keccak256, to_b32, N_MASK,
    _build_hypertree_d2, VARIANTS
)

def keccak256_bytes(data: bytes) -> bytes:
    h = _keccak_mod.new(digest_bits=256)
    h.update(data)
    return h.digest()

def eprint(*a, **kw):
    print(*a, file=sys.stderr, **kw)

# ================================================================
# Constants
# ================================================================
SMART_ACCOUNT = "0x36e6c47f4B43e50DfADde72363706d7B44F49571"
ENTRY_POINT = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"
CHAIN_ID = 84532  # Base Sepolia

# Main signer keys (from test vector generation)
MAIN_ENTROPY = keccak256(b"test_main_key_v1")
MAIN_SEED = keccak256(b"pk_seed" + to_b32(MAIN_ENTROPY)) & N_MASK
MAIN_SK_SEED = keccak256(b"sk_seed" + to_b32(MAIN_ENTROPY))

# ================================================================
# Load test vectors for public keys + compute pkRoot
# ================================================================
with open(os.path.join(os.path.dirname(__file__), "..", "test", "test_vectors.json")) as f:
    vectors = json.load(f)

MAIN_PK_SEED = int(vectors["main"]["pkSeed"], 16)
MAIN_PK_ROOT = int(vectors["main"]["pkRoot"], 16)

eprint(f"Main pkSeed: {hex(MAIN_PK_SEED)[:18]}...")
eprint(f"Main pkRoot: {hex(MAIN_PK_ROOT)[:18]}...")

# ================================================================
# Build the UserOp
# ================================================================
sender = bytes.fromhex(SMART_ACCOUNT[2:])

# callData: execute(address target, uint256 value, bytes data)
# target = self, value = 0, data = "" (empty)
execute_selector = keccak256_bytes(b"execute(address,uint256,bytes)")[:4]
# ABI encode: address (padded), uint256 (0), offset to bytes (96), length (0)
call_data = (
    execute_selector +
    bytes(12) + sender +           # address target (padded to 32 bytes)
    bytes(32) +                     # uint256 value = 0
    (96).to_bytes(32, "big") +     # offset to bytes data (3 * 32 = 96)
    bytes(32)                       # bytes length = 0
)

nonce = 1
init_code = b""
call_gas_limit = 100_000
verification_gas_limit = 800_000  # SPHINCS verification is expensive
pre_verification_gas = 200_000
max_fee_per_gas = 10_000_000  # 10 gwei (generous for testnet)
max_priority_fee_per_gas = 2_000_000  # 2 gwei
paymaster_and_data = b""

eprint(f"callData ({len(call_data)} bytes): 0x{call_data.hex()[:40]}...")

# ================================================================
# Compute userOpHash (EntryPoint v0.6)
# ================================================================
# pack(userOp) per EIP-4337 v0.6:
# keccak256(sender, nonce, keccak256(initCode), keccak256(callData),
#           callGasLimit, verificationGasLimit, preVerificationGas,
#           maxFeePerGas, maxPriorityFeePerGas, keccak256(paymasterAndData))

def pad32(val, size=32):
    if isinstance(val, int):
        return val.to_bytes(size, "big")
    if isinstance(val, bytes):
        return bytes(size - len(val)) + val
    raise TypeError

pack_fields = (
    pad32(sender) +
    pad32(nonce) +
    keccak256_bytes(init_code) +
    keccak256_bytes(call_data) +
    pad32(call_gas_limit) +
    pad32(verification_gas_limit) +
    pad32(pre_verification_gas) +
    pad32(max_fee_per_gas) +
    pad32(max_priority_fee_per_gas) +
    keccak256_bytes(paymaster_and_data)
)

pack_hash = keccak256_bytes(pack_fields)

# userOpHash = keccak256(abi.encode(packHash, entryPoint, chainId))
entry_point_bytes = bytes.fromhex(ENTRY_POINT[2:])
user_op_hash_preimage = (
    pack_hash +
    pad32(entry_point_bytes) +
    pad32(CHAIN_ID)
)
user_op_hash = keccak256_bytes(user_op_hash_preimage)
user_op_hash_int = int.from_bytes(user_op_hash, "big")

eprint(f"userOpHash: 0x{user_op_hash.hex()}")

# ================================================================
# Sign with SPHINCS+C7 main key
# ================================================================
eprint("\nSigning userOpHash with main key (this takes a while)...")
sig_bytes = sign_with_known_keys("c7", user_op_hash_int, MAIN_SEED, MAIN_SK_SEED, MAIN_PK_ROOT)
eprint(f"Signature: {len(sig_bytes)} bytes")

# ================================================================
# ABI-encode PQSignatureWrapper
# ================================================================
# struct PQSignatureWrapper {
#     SignerType signerType;  // uint8 -> padded to uint256 (0 = MAIN)
#     uint32 keyIndex;        // padded to uint256
#     uint32 otsIndex;        // padded to uint256
#     bytes32 pkSeed;
#     bytes32 pkRoot;
#     bytes signature;        // dynamic
# }
# ABI encoding of a struct with a dynamic field:
# - signerType (32 bytes, enum as uint8 padded)
# - keyIndex (32 bytes)
# - otsIndex (32 bytes)
# - pkSeed (32 bytes)
# - pkRoot (32 bytes)
# - offset to signature data (32 bytes) = 6*32 = 192
# - signature length (32 bytes)
# - signature data (padded to 32 bytes)

signer_type = 0  # MAIN
key_index = 0
ots_index = 1

sig_padded = sig_bytes + bytes((-len(sig_bytes)) % 32)  # pad to 32-byte multiple

wrapper = (
    pad32(signer_type) +   # signerType
    pad32(key_index) +     # keyIndex
    pad32(ots_index) +     # otsIndex
    to_b32(MAIN_PK_SEED) + # pkSeed
    to_b32(MAIN_PK_ROOT) + # pkRoot
    pad32(192) +           # offset to signature bytes (6 * 32)
    pad32(len(sig_bytes)) + # signature length
    sig_padded              # signature data
)

# The full UserOp.signature field is abi.encode(PQSignatureWrapper)
# Since it's a struct, we need to wrap it in a tuple offset
# Actually, abi.decode(signature, (PQSignatureWrapper)) expects:
# offset to tuple (32 bytes) + tuple contents
full_sig = pad32(32) + wrapper  # offset to the struct + struct data

eprint(f"PQSignatureWrapper encoded: {len(full_sig)} bytes")
eprint(f"Signature hex: 0x{full_sig.hex()[:40]}...")

# ================================================================
# Output handleOps calldata
# ================================================================
# We need to ABI-encode: handleOps(UserOperation[] calldata ops, address payable beneficiary)
#
# UserOperation struct (v0.6):
# address sender, uint256 nonce, bytes initCode, bytes callData,
# uint256 callGasLimit, uint256 verificationGasLimit, uint256 preVerificationGas,
# uint256 maxFeePerGas, uint256 maxPriorityFeePerGas, bytes paymasterAndData, bytes signature

# Output individual fields for cast
eprint("\n=== Cast command parameters ===")
print(json.dumps({
    "sender": SMART_ACCOUNT,
    "nonce": nonce,
    "initCode": "0x",
    "callData": "0x" + call_data.hex(),
    "callGasLimit": call_gas_limit,
    "verificationGasLimit": verification_gas_limit,
    "preVerificationGas": pre_verification_gas,
    "maxFeePerGas": max_fee_per_gas,
    "maxPriorityFeePerGas": max_priority_fee_per_gas,
    "paymasterAndData": "0x",
    "signature": "0x" + full_sig.hex(),
    "userOpHash": "0x" + user_op_hash.hex(),
}))
