#!/usr/bin/env python3
"""
Reference SPHINCS+ signer for tweaked variants from ePrint 2025/2203.
Produces valid signatures verifiable by the Solidity/Assembly contracts.

Adapted from https://github.com/nconsigny/SPHINCs-/blob/main/script/signer.py
"""

import sys
import struct
import time
import multiprocessing
from Crypto.Hash import keccak as _keccak_mod

# ============================================================
#  Constants
# ============================================================

N = 16  # n = 128 bits = 16 bytes
N_MASK = (1 << 256) - (1 << 128)  # top 128 bits of uint256
FULL = (1 << 256) - 1

ADRS_WOTS = 0
ADRS_WOTS_PK = 1
ADRS_TREE = 2
ADRS_FORS_TREE = 3
ADRS_FORS_ROOTS = 4
ADRS_PORS = 5

W = 16
LOG_W = 4
L = 32
LEN1 = 32
TARGET_SUM = 240
Z = 0
W_MASK = 0xF

VARIANTS = {
    "c2": {"h": 18, "d": 2, "k": 13, "a": 13, "m_max": 0,   "scheme": "fors",
            "subtree_h": 9, "sig_size": 4040},
    "c6": {"h": 24, "d": 2, "k": 8, "a": 16, "m_max": 0, "scheme": "fors",
            "subtree_h": 12, "sig_size": 3352},
    "c7": {"h": 24, "d": 2, "k": 8, "a": 16, "m_max": 0, "scheme": "fors",
            "subtree_h": 12, "sig_size": 3976,
            "w": 8, "log_w": 3, "l": 43, "den1": 43, "target_sum": 151, "w_mask": 0x7},
    "c8": {"h": 20, "d": 2, "k": 12, "a": 13, "m_max": 0, "scheme": "fors",
            "subtree_h": 10, "sig_size": 3848,
            "w": 16, "log_w": 4, "l": 32, "den1": 32, "target_sum": 162, "w_mask": 0xF},
    "c9": {"h": 20, "d": 2, "k": 11, "a": 12, "m_max": 0, "scheme": "fors",
            "subtree_h": 10, "sig_size": 3816,
            "w": 8, "log_w": 3, "l": 43, "den1": 43, "target_sum": 208, "w_mask": 0x7},
    "c10": {"h": 18, "d": 2, "k": 13, "a": 11, "m_max": 0, "scheme": "fors",
            "subtree_h": 9, "sig_size": 4008,
            "w": 8, "log_w": 3, "l": 43, "den1": 43, "target_sum": 205, "w_mask": 0x7},
    "c11": {"h": 16, "d": 2, "k": 13, "a": 11, "m_max": 0, "scheme": "fors",
            "subtree_h": 8, "sig_size": 3976,
            "w": 8, "log_w": 3, "l": 43, "den1": 43, "target_sum": 203, "w_mask": 0x7},
}

# ============================================================
#  Keccak256 Primitive
# ============================================================

def keccak256(data: bytes) -> int:
    h = _keccak_mod.new(digest_bits=256)
    h.update(data)
    return int.from_bytes(h.digest(), "big")

def to_b32(val: int) -> bytes:
    return (val & FULL).to_bytes(32, "big")

def to_b4(val: int) -> bytes:
    return struct.pack(">I", val & 0xFFFFFFFF)

_BUF96 = bytearray(96)
_BUF128 = bytearray(128)

def _keccak_3x32(a: int, b: int, c: int) -> int:
    _BUF96[0:32] = a.to_bytes(32, "big")
    _BUF96[32:64] = b.to_bytes(32, "big")
    _BUF96[64:96] = c.to_bytes(32, "big")
    h = _keccak_mod.new(digest_bits=256)
    h.update(_BUF96)
    return int.from_bytes(h.digest(), "big")

def _keccak_4x32(a: int, b: int, c: int, d: int) -> int:
    _BUF128[0:32] = a.to_bytes(32, "big")
    _BUF128[32:64] = b.to_bytes(32, "big")
    _BUF128[64:96] = c.to_bytes(32, "big")
    _BUF128[96:128] = d.to_bytes(32, "big")
    h = _keccak_mod.new(digest_bits=256)
    h.update(_BUF128)
    return int.from_bytes(h.digest(), "big")

# ============================================================
#  Tweakable Hash Primitives
# ============================================================

def make_adrs(layer, tree, atype, kp, ci, cp, ha):
    return ((layer & 0xFFFFFFFF) << 224 |
            (tree & 0xFFFFFFFFFFFFFFFF) << 160 |
            (atype & 0xFFFFFFFF) << 128 |
            (kp & 0xFFFFFFFF) << 96 |
            (ci & 0xFFFFFFFF) << 64 |
            (cp & 0xFFFFFFFF) << 32 |
            (ha & 0xFFFFFFFF))

def th(seed, adrs, inp):
    return _keccak_3x32(seed, adrs, inp) & N_MASK

def th_pair(seed, adrs, left, right):
    return _keccak_4x32(seed, adrs, left, right) & N_MASK

def th_multi(seed, adrs, vals):
    data = to_b32(seed) + to_b32(adrs)
    for v in vals:
        data += to_b32(v)
    return keccak256(data) & N_MASK

HMSG_DOMAIN = (1 << 256) - 1

def h_msg(seed, root, R, message):
    data = to_b32(seed) + to_b32(root) + to_b32(R) + to_b32(message) + to_b32(HMSG_DOMAIN)
    return keccak256(data)

def chain_hash(seed, adrs, val, start_pos, steps):
    pos_clear = FULL ^ (0xFFFFFFFF << 32)
    for step in range(steps):
        pos = start_pos + step
        a = (adrs & pos_clear) | ((pos & 0xFFFFFFFF) << 32)
        val = _keccak_3x32(seed, a, val) & N_MASK
    return val

def set_chain_index(adrs, idx):
    mask = FULL ^ (0xFFFFFFFF << 64)
    return (adrs & mask) | ((idx & 0xFFFFFFFF) << 64)

# ============================================================
#  Key Derivation
# ============================================================

def derive_keys(message_int):
    entropy = keccak256(b"sphincs_signer_v1" + to_b32(message_int))
    seed = keccak256(b"pk_seed" + to_b32(entropy)) & N_MASK
    sk_seed = keccak256(b"sk_seed" + to_b32(entropy))
    return seed, sk_seed

def wots_secret(sk_seed, layer, tree, kp, chain_idx):
    data = (to_b32(sk_seed) + b"wots" +
            to_b4(layer) + to_b32(tree) + to_b4(kp) + to_b4(chain_idx))
    return keccak256(data) & N_MASK

def fors_secret(sk_seed, tree_idx, leaf_idx):
    data = to_b32(sk_seed) + b"fors" + to_b4(tree_idx) + to_b4(leaf_idx)
    return keccak256(data) & N_MASK

# ============================================================
#  WOTS+C
# ============================================================

def _wots_params(cfg=None):
    if cfg and "w" in cfg:
        w = cfg["w"]
        return w, cfg["log_w"], cfg["l"], cfg["den1"], cfg["target_sum"], cfg["w_mask"]
    return W, LOG_W, L, LEN1, TARGET_SUM, W_MASK

def wots_keygen_pk_only(seed, sk_seed, layer, tree, kp, cfg=None):
    w, _, l, _, _, _ = _wots_params(cfg)
    base_adrs = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0)
    pk_elements = []
    for i in range(l):
        sk_i = wots_secret(sk_seed, layer, tree, kp, i)
        chain_adrs = set_chain_index(base_adrs, i)
        pk_i = chain_hash(seed, chain_adrs, sk_i, 0, w - 1)
        pk_elements.append(pk_i)
    pk_adrs = make_adrs(layer, tree, ADRS_WOTS_PK, kp, 0, 0, 0)
    return th_multi(seed, pk_adrs, pk_elements)

def wots_keygen(seed, sk_seed, layer, tree, kp, cfg=None):
    w, _, l, _, _, _ = _wots_params(cfg)
    base_adrs = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0)
    sk = []
    pk_elements = []
    for i in range(l):
        sk_i = wots_secret(sk_seed, layer, tree, kp, i)
        sk.append(sk_i)
        chain_adrs = set_chain_index(base_adrs, i)
        pk_i = chain_hash(seed, chain_adrs, sk_i, 0, w - 1)
        pk_elements.append(pk_i)
    pk_adrs = make_adrs(layer, tree, ADRS_WOTS_PK, kp, 0, 0, 0)
    wots_pk = th_multi(seed, pk_adrs, pk_elements)
    return sk, wots_pk

def wots_digest(seed, layer, tree, kp, msg_hash, count):
    hash_adrs = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0)
    return _keccak_4x32(seed, hash_adrs, msg_hash, count)

def extract_digits(d, cfg=None):
    _, log_w, _, den1, _, w_mask = _wots_params(cfg)
    return [(d >> (i * log_w)) & w_mask for i in range(den1)]

def wots_find_count(seed, layer, tree, kp, msg_hash, cfg=None):
    _, _, _, _, target_sum, _ = _wots_params(cfg)
    for count in range(10_000_000):
        d = wots_digest(seed, layer, tree, kp, msg_hash, count)
        digits = extract_digits(d, cfg)
        if sum(digits) == target_sum:
            return count, d, digits
    raise RuntimeError("WOTS+C count grinding failed")

def wots_sign(seed, sk, layer, tree, kp, msg_hash, cfg=None):
    w, _, l, _, _, _ = _wots_params(cfg)
    count, d, digits = wots_find_count(seed, layer, tree, kp, msg_hash, cfg)
    base_adrs = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0)
    sigma = []
    for i in range(l):
        chain_adrs = set_chain_index(base_adrs, i)
        sigma_i = chain_hash(seed, chain_adrs, sk[i], 0, digits[i])
        sigma.append(sigma_i)
    return sigma, count

# ============================================================
#  Merkle Trees
# ============================================================

def build_merkle_tree(seed, layer, tree, leaves, height):
    nodes = [list(leaves)]
    for h in range(height):
        prev = nodes[h]
        level = []
        for j in range(0, len(prev), 2):
            parent_idx = j // 2
            adrs = make_adrs(layer, tree, ADRS_TREE, 0, 0, h + 1, parent_idx)
            level.append(th_pair(seed, adrs, prev[j], prev[j + 1]))
        nodes.append(level)
    return nodes

def get_auth_path(tree_nodes, leaf_idx, height):
    path = []
    idx = leaf_idx
    for h in range(height):
        path.append(tree_nodes[h][idx ^ 1])
        idx >>= 1
    return path

# ============================================================
#  Hypertree
# ============================================================

def build_subtree_root(seed, sk_seed, layer, tree, subtree_h, cfg=None):
    n_leaves = 1 << subtree_h
    leaves = []
    for kp in range(n_leaves):
        pk = wots_keygen_pk_only(seed, sk_seed, layer, tree, kp, cfg)
        leaves.append(pk)
    nodes = build_merkle_tree(seed, layer, tree, leaves, subtree_h)
    return nodes[subtree_h][0]

def build_subtree_full(seed, sk_seed, layer, tree, subtree_h, cfg=None):
    n_leaves = 1 << subtree_h
    wots_sks = []
    leaves = []
    for kp in range(n_leaves):
        sk, pk = wots_keygen(seed, sk_seed, layer, tree, kp, cfg)
        wots_sks.append(sk)
        leaves.append(pk)
    nodes = build_merkle_tree(seed, layer, tree, leaves, subtree_h)
    return wots_sks, nodes, nodes[subtree_h][0]

# ============================================================
#  FORS+C
# ============================================================

def build_fors_tree(seed, sk_seed, tree_idx, a):
    n_leaves = 1 << a
    leaves = []
    for j in range(n_leaves):
        secret = fors_secret(sk_seed, tree_idx, j)
        leaf_adrs = make_adrs(0, 0, ADRS_FORS_TREE, tree_idx, 0, 0, j)
        leaves.append(th(seed, leaf_adrs, secret))
    nodes = [leaves]
    for h in range(a):
        prev = nodes[h]
        level = []
        for idx in range(0, len(prev), 2):
            parent_idx = idx // 2
            adrs = make_adrs(0, 0, ADRS_FORS_TREE, tree_idx, 0, h + 1, parent_idx)
            level.append(th_pair(seed, adrs, prev[idx], prev[idx + 1]))
        nodes.append(level)
    return nodes, nodes[a][0]

def fors_sign_full(seed, sk_seed, digest, k, a):
    a_mask = (1 << a) - 1
    indices = [(digest >> (i * a)) & a_mask for i in range(k)]
    assert indices[k - 1] == 0, f"Forced-zero violated: last index = {indices[k-1]}"

    secrets = []
    auth_paths = []
    roots = []

    for t in range(k - 1):
        eprint(f"  FORS tree {t}/{k-1}...")
        tree_nodes, root = build_fors_tree(seed, sk_seed, t, a)
        secrets.append(fors_secret(sk_seed, t, indices[t]))
        auth_paths.append(get_auth_path(tree_nodes, indices[t], a))
        roots.append(root)

    eprint(f"  FORS tree {k-1}/{k-1} (forced-zero)...")
    _, root_last = build_fors_tree(seed, sk_seed, k - 1, a)
    secrets.append(root_last)
    roots.append(th(seed, make_adrs(0, 0, ADRS_FORS_TREE, k - 1, 0, 0, 0), root_last))

    roots_adrs = make_adrs(0, 0, ADRS_FORS_ROOTS, 0, 0, 0, 0)
    fors_pk = th_multi(seed, roots_adrs, roots)
    return secrets, auth_paths, fors_pk

# ============================================================
#  R Grinding
# ============================================================

def grind_R_fors(seed, root, message, k, a):
    a_mask = (1 << a) - 1
    last_shift = (k - 1) * a
    for nonce in range(10_000_000):
        R = keccak256(b"R_grind" + to_b32(nonce)) & N_MASK
        digest = h_msg(seed, root, R, message)
        if (digest >> last_shift) & a_mask == 0:
            eprint(f"  R grind: found at nonce={nonce}")
            return R, digest
    raise RuntimeError("R grinding failed")

# ============================================================
#  Utility
# ============================================================

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

# ============================================================
#  Full Signing
# ============================================================

def sign_variant(variant_name, message_int, seed=None, sk_seed=None, pk_root=None):
    cfg = VARIANTS[variant_name]
    d = cfg["d"]
    k = cfg["k"]
    a = cfg["a"]
    m_max = cfg["m_max"]
    subtree_h = cfg["subtree_h"]
    scheme = cfg["scheme"]
    h = cfg["h"]
    sig_size = cfg["sig_size"]

    if seed is None or sk_seed is None:
        seed, sk_seed = derive_keys(message_int)
    eprint(f"Signing {variant_name}: scheme={scheme}, h={h}, d={d}, k={k}, a={a}")
    eprint(f"  seed = {hex(seed)[:18]}...")

    if pk_root is None:
        pk_root = _build_hypertree_d2(seed, sk_seed, subtree_h, cfg)

    eprint(f"  pkRoot = {hex(pk_root)[:18]}...")

    # Grind R
    R, digest = grind_R_fors(seed, pk_root, message_int, k, a)

    # Decompose hypertree path
    ht_shift = k * a
    ht_mask = (1 << h) - 1
    htIdx = (digest >> ht_shift) & ht_mask

    path_info = []
    idx_tree = htIdx
    for lay in range(d):
        idx_leaf = idx_tree & ((1 << subtree_h) - 1)
        idx_tree_next = idx_tree >> subtree_h
        path_info.append((lay, idx_tree_next, idx_leaf))
        idx_tree = idx_tree_next

    eprint(f"  htIdx={htIdx}, path={path_info}")

    # Sign FORS+C
    eprint("  Signing FORS+C...")
    fors_secrets, fors_auth_paths, bottom_pk = fors_sign_full(seed, sk_seed, digest, k, a)

    # Sign Hypertree
    eprint("  Signing hypertree...")
    ht_layers = []
    current_node = bottom_pk
    idx_tree = htIdx

    for lay in range(d):
        idx_leaf = idx_tree & ((1 << subtree_h) - 1)
        idx_tree = idx_tree >> subtree_h

        eprint(f"    Building subtree layer={lay} tree={idx_tree}...")
        wots_sks, tree_nodes, _ = build_subtree_full(seed, sk_seed, lay, idx_tree, subtree_h, cfg)

        sigma, count = wots_sign(seed, wots_sks[idx_leaf], lay, idx_tree, idx_leaf, current_node, cfg)
        auth_path = get_auth_path(tree_nodes, idx_leaf, subtree_h)
        ht_layers.append((sigma, count, auth_path))

        # Verify internally
        vw, _, vl, _, _, _ = _wots_params(cfg)
        d_val = wots_digest(seed, lay, idx_tree, idx_leaf, current_node, count)
        digits = extract_digits(d_val, cfg)
        base_adrs = make_adrs(lay, idx_tree, ADRS_WOTS, idx_leaf, 0, 0, 0)
        pk_elements = []
        for i in range(vl):
            ca = set_chain_index(base_adrs, i)
            pk_elements.append(chain_hash(seed, ca, sigma[i], digits[i], vw - 1 - digits[i]))
        pk_adrs = make_adrs(lay, idx_tree, ADRS_WOTS_PK, idx_leaf, 0, 0, 0)
        wots_pk_v = th_multi(seed, pk_adrs, pk_elements)

        node = wots_pk_v
        m_idx = idx_leaf
        for hh in range(subtree_h):
            sib = auth_path[hh]
            pi = m_idx >> 1
            adrs = make_adrs(lay, idx_tree, ADRS_TREE, 0, 0, hh + 1, pi)
            node = th_pair(seed, adrs, node, sib) if m_idx & 1 == 0 else th_pair(seed, adrs, sib, node)
            m_idx >>= 1
        current_node = node
        eprint(f"    Layer {lay}: root = {hex(current_node)[:18]}...")

    assert current_node == pk_root, \
        f"Root mismatch: {hex(current_node)} != {hex(pk_root)}"
    eprint("  Root verified!")

    # Pack Signature
    sig = b""
    sig += to_b32(R)[:N]

    for s in fors_secrets:
        sig += to_b32(s)[:N]
    for path in fors_auth_paths:
        for node in path:
            sig += to_b32(node)[:N]

    for sigma, count, auth_path in ht_layers:
        for s in sigma:
            sig += to_b32(s)[:N]
        sig += to_b4(count)
        for node in auth_path:
            sig += to_b32(node)[:N]

    assert len(sig) == sig_size, f"Sig size: {len(sig)} != {sig_size}"
    eprint(f"  Signature: {len(sig)} bytes")

    return seed, pk_root, sig


def sign_with_known_keys(variant_name, message_int, seed, sk_seed, pk_root):
    _, _, sig = sign_variant(variant_name, message_int, seed=seed, sk_seed=sk_seed, pk_root=pk_root)
    return sig


def _build_hypertree_d2(seed, sk_seed, subtree_h, cfg=None):
    eprint(f"  Computing pkRoot (1 subtree at top layer)...")
    t0 = time.time()
    pk_root = build_subtree_root(seed, sk_seed, 1, 0, subtree_h, cfg)
    eprint(f"  pkRoot done: {time.time()-t0:.1f}s")
    return pk_root
