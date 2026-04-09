#!/usr/bin/env python3
"""Generate SPHINCS+C7 test vectors for Foundry gas benchmarks.
Outputs Solidity-compatible hex constants for:
  - Bootstrap key pair (pkSeed, pkRoot)
  - Main key pair (pkSeed, pkRoot)
  - A bootstrap signature over an auth message (factory createAccount)
  - A main signature over a userOpHash (validateUserOp)
"""
import sys, os, time, json

# Add the signer from nconsigny's repo
sys.path.insert(0, os.path.dirname(__file__))
from signer_c7 import (
    sign_variant, derive_keys, keccak256, to_b32, N_MASK,
    _build_hypertree_d2, VARIANTS, sign_with_known_keys
)

def eprint(*a, **kw):
    print(*a, file=sys.stderr, **kw)

def hex32(v):
    """Format a 256-bit int as 0x-prefixed 32-byte hex."""
    return "0x" + (v & ((1 << 256) - 1)).to_bytes(32, "big").hex()

def bytes_to_hex(b):
    return "0x" + b.hex()

cfg = VARIANTS["c7"]

# ================================================================
# 1. Generate bootstrap key pair
# ================================================================
eprint("=== Generating bootstrap key pair ===")
t0 = time.time()
bootstrap_entropy = keccak256(b"test_bootstrap_key_v1")
bootstrap_seed = keccak256(b"pk_seed" + to_b32(bootstrap_entropy)) & N_MASK
bootstrap_sk_seed = keccak256(b"sk_seed" + to_b32(bootstrap_entropy))
eprint(f"  bootstrap_seed = {hex32(bootstrap_seed)[:18]}...")
eprint(f"  Building bootstrap pkRoot...")
bootstrap_root = _build_hypertree_d2(bootstrap_seed, bootstrap_sk_seed, cfg["subtree_h"], cfg)
eprint(f"  bootstrap_root = {hex32(bootstrap_root)[:18]}...")
eprint(f"  Bootstrap keygen: {time.time()-t0:.1f}s")

# ================================================================
# 2. Generate main key pair
# ================================================================
eprint("\n=== Generating main key pair ===")
t0 = time.time()
main_entropy = keccak256(b"test_main_key_v1")
main_seed = keccak256(b"pk_seed" + to_b32(main_entropy)) & N_MASK
main_sk_seed = keccak256(b"sk_seed" + to_b32(main_entropy))
eprint(f"  main_seed = {hex32(main_seed)[:18]}...")
eprint(f"  Building main pkRoot...")
main_root = _build_hypertree_d2(main_seed, main_sk_seed, cfg["subtree_h"], cfg)
eprint(f"  main_root = {hex32(main_root)[:18]}...")
eprint(f"  Main keygen: {time.time()-t0:.1f}s")

# ================================================================
# 3. Sign factory auth message with bootstrap key
#    authMsg = keccak256("PQWALLET_INIT_V1" || mainPkSeed || mainPkRoot)
# ================================================================
eprint("\n=== Signing factory auth message (bootstrap) ===")
t0 = time.time()
auth_msg_preimage = b"PQWALLET_INIT_V1" + to_b32(main_seed) + to_b32(main_root)
auth_msg = keccak256(auth_msg_preimage)
# The verifier expects a bytes32 message, so we pass the keccak256 hash
auth_msg_b32 = auth_msg  # already a 256-bit int
eprint(f"  authMsg = {hex32(auth_msg_b32)[:18]}...")

bootstrap_sig = sign_with_known_keys("c7", auth_msg_b32, bootstrap_seed, bootstrap_sk_seed, bootstrap_root)
eprint(f"  Bootstrap sig: {len(bootstrap_sig)} bytes")
eprint(f"  Bootstrap signing: {time.time()-t0:.1f}s")

# ================================================================
# 4. Sign a userOpHash with main key
# ================================================================
eprint("\n=== Signing userOpHash (main) ===")
t0 = time.time()
user_op_hash = keccak256(b"test_user_op_hash_v1")
eprint(f"  userOpHash = {hex32(user_op_hash)[:18]}...")

main_sig = sign_with_known_keys("c7", user_op_hash, main_seed, main_sk_seed, main_root)
eprint(f"  Main sig: {len(main_sig)} bytes")
eprint(f"  Main signing: {time.time()-t0:.1f}s")

# ================================================================
# 5. Sign a second userOpHash with bootstrap key (for rotation test)
# ================================================================
eprint("\n=== Signing rotation userOpHash (bootstrap) ===")
t0 = time.time()
rotation_hash = keccak256(b"test_rotation_hash_v1")
eprint(f"  rotationHash = {hex32(rotation_hash)[:18]}...")

bootstrap_sig2 = sign_with_known_keys("c7", rotation_hash, bootstrap_seed, bootstrap_sk_seed, bootstrap_root)
eprint(f"  Bootstrap sig2: {len(bootstrap_sig2)} bytes")
eprint(f"  Bootstrap rotation signing: {time.time()-t0:.1f}s")

# ================================================================
# Output JSON test vectors
# ================================================================
vectors = {
    "bootstrap": {
        "pkSeed": hex32(bootstrap_seed),
        "pkRoot": hex32(bootstrap_root),
    },
    "main": {
        "pkSeed": hex32(main_seed),
        "pkRoot": hex32(main_root),
    },
    "factoryAuthMsg": hex32(auth_msg_b32),
    "bootstrapSig": bytes_to_hex(bootstrap_sig),
    "userOpHash": hex32(user_op_hash),
    "mainSig": bytes_to_hex(main_sig),
    "rotationHash": hex32(rotation_hash),
    "bootstrapSig2": bytes_to_hex(bootstrap_sig2),
}

print(json.dumps(vectors, indent=2))
eprint("\nDone! Test vectors written to stdout.")
