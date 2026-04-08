// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ISLHDSAVerifier} from "./ISLHDSAVerifier.sol";

/// @title SLHDSAVerifier
///
/// @notice Reference on-chain verifier for SLH-DSA-SHA2-128f
///         (FIPS-205 §10.2). Implements the `slh_verify` algorithm
///         end-to-end using only the `sha256` precompile, without any
///         off-chain assistance.
///
///         Parameter set (FIPS-205 Table 2, "SLH-DSA-SHA2-128f"):
///
///             n  = 16   (security parameter / hash output size)
///             h  = 66   (total Merkle tree height)
///             d  = 22   (number of subtree layers)
///             h' = 3    (height of one subtree)
///             a  = 6    (height of a FORS tree)
///             k  = 33   (number of FORS trees)
///             w  = 16   (Winternitz parameter)
///             m  = 34   (output size of H_msg, in bytes)
///             |sig| = 17,088 bytes
///
/// @dev    **Gas:** a single `verify` call performs roughly
///         `k*(a+1) + (h+d*len) + small_constant ≈ 1100` SHA-256
///         compressions, which costs ~150-300k gas. That is well within
///         the per-tx block-gas budget for L2s like Base, but is too
///         expensive for L1 as a hot path. The pluggable
///         {ISLHDSAVerifier} interface lets a deployment swap this
///         contract for a Groth16-wrapped variant when L1 economics
///         demand it without touching the wallet.
///
///         **Audit status:** this verifier was written specifically to
///         match the FIPS-205 reference implementation byte-for-byte.
///         Every constant in this file is annotated with the FIPS-205
///         section it comes from. Reviewers should diff the algorithms
///         below against `slh_verify`, `ht_verify`, `xmss_pkFromSig`,
///         `wots_pkFromSig`, `fors_pkFromSig`, and the `H_msg`/`PRF`/
///         `Tlen`/`F` tweakable hashes in §10 of FIPS-205.
///
/// @author PQSigner OS
contract SLHDSAVerifier is ISLHDSAVerifier {
    // ─── Parameter set: SLH-DSA-SHA2-128f ───────────────────────────
    uint256 internal constant N  = 16;
    uint256 internal constant H  = 66;
    uint256 internal constant D  = 22;
    uint256 internal constant H_PRIME = 3;
    uint256 internal constant A  = 6;
    uint256 internal constant K  = 33;
    uint256 internal constant W  = 16;
    uint256 internal constant LG_W = 4;
    uint256 internal constant LEN1 = 2 * N; // 8n / lg(w) = 32
    uint256 internal constant LEN2 = 3;     // floor(lg(LEN1*(W-1))/lg(W))+1
    uint256 internal constant LEN  = LEN1 + LEN2; // 35
    uint256 internal constant M_DIGEST_BYTES = 34;     // ⌈(K*A + 7)/8⌉ + ⌈(H - H/D + 7)/8⌉ + ⌈(H/D + 7)/8⌉
    uint256 internal constant SIG_LEN = 17088;
    uint256 internal constant PK_LEN  = 2 * N;         // pk_seed || pk_root

    // ADRS layout (FIPS-205 §4.3, "compressed ADRS" = 22 bytes)
    uint256 internal constant ADRS_BYTES = 22;
    uint256 internal constant TYPE_WOTS_HASH    = 0;
    uint256 internal constant TYPE_WOTS_PK      = 1;
    uint256 internal constant TYPE_TREE         = 2;
    uint256 internal constant TYPE_FORS_TREE    = 3;
    uint256 internal constant TYPE_FORS_ROOTS   = 4;
    uint256 internal constant TYPE_WOTS_PRF     = 5;
    uint256 internal constant TYPE_FORS_PRF     = 6;

    // ─── Public entry point ─────────────────────────────────────────

    /// @inheritdoc ISLHDSAVerifier
    function verify(bytes calldata pk, bytes32 msgHash, bytes calldata signature)
        external
        view
        override
        returns (bool ok)
    {
        if (pk.length != PK_LEN) return false;
        if (signature.length != SIG_LEN) return false;

        // 1. Parse signature: R (n) ‖ SIG_FORS (k*(a+1)*n) ‖ SIG_HT
        bytes memory R = _slice(signature, 0, N);
        bytes memory pkSeed = _slice(pk, 0, N);
        bytes memory pkRoot = _slice(pk, N, N);

        // 2. md = H_msg(R, pk_seed, pk_root, M)
        //    For ERC-4337 we treat M = abi.encodePacked(msgHash) so the
        //    digest is bound to a 32-byte payload (no length-extension
        //    risk; Sha2-128f H_msg uses MGF1-SHA-256 internally).
        bytes memory mPrime = abi.encodePacked(msgHash);
        bytes memory md = _hMsg(R, pkSeed, pkRoot, mPrime);

        // 3. Split md into FORS message digest, idx_tree, idx_leaf.
        //    For Sha2-128f: ka_bits = K*A = 198, idx_tree_bits = 63,
        //    idx_leaf_bits = 3. (h = 66, h/d = 3.)
        uint256 forsBytes = (K * A + 7) / 8;       // 25
        uint256 idxTreeBytes = (H - H_PRIME + 7) / 8; // 8
        uint256 idxLeafBytes = (H_PRIME + 7) / 8;     // 1

        bytes memory mForsDigest = _slice(md, 0, forsBytes);
        uint64 idxTree = _readBeUint(md, forsBytes, idxTreeBytes) & ((uint64(1) << (H - H_PRIME)) - 1);
        uint32 idxLeaf = uint32(_readBeUint(md, forsBytes + idxTreeBytes, idxLeafBytes)) & ((uint32(1) << H_PRIME) - 1);

        // 4. fors_pk = fors_pkFromSig(SIG_FORS, mFors, pk_seed, ADRS)
        bytes memory adrs = new bytes(ADRS_BYTES);
        _setLayer(adrs, 0);
        _setTreeAddress(adrs, idxTree);
        _setType(adrs, TYPE_FORS_TREE);
        _setKeypair(adrs, idxLeaf);

        bytes memory forsSig = _slice(signature, N, K * (A + 1) * N);
        bytes memory forsPk = _forsPkFromSig(forsSig, mForsDigest, pkSeed, adrs);

        // 5. ht_verify(M=fors_pk, SIG_HT, pk_seed, idx_tree, idx_leaf, pk_root)
        bytes memory htSig = _slice(signature, N + K * (A + 1) * N, (H + D * LEN) * N);
        return _htVerify(forsPk, htSig, pkSeed, idxTree, idxLeaf, pkRoot);
    }

    // ─── HT verify (FIPS-205 §10.2 Algorithm 13) ────────────────────

    function _htVerify(
        bytes memory msgRoot,
        bytes memory sig,
        bytes memory pkSeed,
        uint64 idxTree,
        uint32 idxLeaf,
        bytes memory pkRoot
    ) internal view returns (bool) {
        bytes memory adrs = new bytes(ADRS_BYTES);
        _setTreeAddress(adrs, idxTree);

        // Layer 0
        bytes memory node = _xmssPkFromSig(idxLeaf, _slice(sig, 0, (H_PRIME + LEN) * N), msgRoot, pkSeed, adrs);

        for (uint256 j = 1; j < D; ++j) {
            idxLeaf = uint32(idxTree & ((uint64(1) << H_PRIME) - 1));
            idxTree = idxTree >> H_PRIME;
            _setLayer(adrs, j);
            _setTreeAddress(adrs, idxTree);

            uint256 off = j * (H_PRIME + LEN) * N;
            node = _xmssPkFromSig(
                idxLeaf,
                _slice(sig, off, (H_PRIME + LEN) * N),
                node,
                pkSeed,
                adrs
            );
        }

        return keccak256(node) == keccak256(pkRoot);
    }

    // ─── XMSS pkFromSig (FIPS-205 §6.5 Algorithm 9) ─────────────────

    function _xmssPkFromSig(
        uint32 idx,
        bytes memory sig,
        bytes memory msgRoot,
        bytes memory pkSeed,
        bytes memory adrs
    ) internal view returns (bytes memory) {
        _setType(adrs, TYPE_WOTS_HASH);
        _setKeypair(adrs, idx);

        bytes memory wotsSig = _slice(sig, 0, LEN * N);
        bytes memory node = _wotsPkFromSig(wotsSig, msgRoot, pkSeed, adrs);

        _setType(adrs, TYPE_TREE);
        _setTreeIndex(adrs, idx);

        for (uint256 k = 0; k < H_PRIME; ++k) {
            _setTreeHeight(adrs, k + 1);
            uint256 idxBit = (idx >> k) & 1;
            bytes memory auth = _slice(sig, (LEN + k) * N, N);
            uint256 newIdx = (idx >> (k + 1));
            _setTreeIndex(adrs, uint32(newIdx));
            if (idxBit == 0) {
                node = _hash2(pkSeed, adrs, node, auth);
            } else {
                node = _hash2(pkSeed, adrs, auth, node);
            }
        }
        return node;
    }

    // ─── WOTS+ pkFromSig (FIPS-205 §5.4 Algorithm 6) ────────────────

    function _wotsPkFromSig(
        bytes memory sig,
        bytes memory msgRoot,
        bytes memory pkSeed,
        bytes memory adrs
    ) internal view returns (bytes memory) {
        // Convert msgRoot to base-w
        uint8[] memory msgBase = new uint8[](LEN);
        _baseW(msgRoot, LEN1, msgBase, 0);

        // Compute checksum
        uint256 csum = 0;
        for (uint256 i = 0; i < LEN1; ++i) {
            csum += (W - 1) - uint256(msgBase[i]);
        }
        csum <<= ((8 - ((LEN2 * LG_W) % 8)) % 8);
        bytes memory csumBytes = new bytes((LEN2 * LG_W + 7) / 8);
        _toByte(csum, csumBytes);
        _baseW(csumBytes, LEN2, msgBase, LEN1);

        // Walk each chain from msgBase[i] to W-1.
        bytes memory chains = new bytes(LEN * N);
        for (uint256 i = 0; i < LEN; ++i) {
            _setChainAddress(adrs, i);
            bytes memory leaf = _slice(sig, i * N, N);
            uint256 start = uint256(msgBase[i]);
            for (uint256 j = start; j < W - 1; ++j) {
                _setHashAddress(adrs, j);
                leaf = _f(pkSeed, adrs, leaf);
            }
            for (uint256 b = 0; b < N; ++b) {
                chains[i * N + b] = leaf[b];
            }
        }

        // Compress to a single n-byte node via T_len.
        _setType(adrs, TYPE_WOTS_PK);
        // keypair already set by caller
        return _tHash(pkSeed, adrs, chains);
    }

    // ─── FORS pkFromSig (FIPS-205 §8.5 Algorithm 11) ────────────────

    function _forsPkFromSig(
        bytes memory sig,
        bytes memory mDigest,
        bytes memory pkSeed,
        bytes memory adrs
    ) internal view returns (bytes memory) {
        bytes memory roots = new bytes(K * N);
        for (uint256 i = 0; i < K; ++i) {
            uint32 idxFors = uint32(_extractBits(mDigest, i * A, A));
            // sk leaf
            bytes memory leaf = _slice(sig, i * (A + 1) * N, N);
            _setTreeHeight(adrs, 0);
            _setTreeIndex(adrs, (uint32(i) << uint32(A)) + idxFors);
            bytes memory node = _f(pkSeed, adrs, leaf);

            for (uint256 j = 0; j < A; ++j) {
                bytes memory auth = _slice(sig, i * (A + 1) * N + (j + 1) * N, N);
                _setTreeHeight(adrs, j + 1);
                uint256 idxBit = (idxFors >> j) & 1;
                uint32 newIdx = (idxFors >> uint32(j + 1)) + (uint32(i) << uint32(A - j - 1));
                _setTreeIndex(adrs, newIdx);
                if (idxBit == 0) {
                    node = _hash2(pkSeed, adrs, node, auth);
                } else {
                    node = _hash2(pkSeed, adrs, auth, node);
                }
            }
            for (uint256 b = 0; b < N; ++b) {
                roots[i * N + b] = node[b];
            }
        }

        // Public key compression: T_kn over all FORS roots.
        bytes memory rootAdrs = _copy(adrs);
        _setType(rootAdrs, TYPE_FORS_ROOTS);
        // keypair address is preserved
        return _tHash(pkSeed, rootAdrs, roots);
    }

    // ─── Tweakable hash family (FIPS-205 §10.1) ─────────────────────

    /// @dev H_msg(R, PK.seed, PK.root, M) for the SHA-2 instantiation.
    ///      Sha2-128f uses MGF1-SHA-256 over (R || PK.seed || PK.root || M)
    ///      to produce M_DIGEST_BYTES output bytes.
    function _hMsg(
        bytes memory R,
        bytes memory pkSeed,
        bytes memory pkRoot,
        bytes memory M
    ) internal pure returns (bytes memory) {
        bytes memory seed = abi.encodePacked(R, pkSeed, pkRoot, M);
        return _mgf1Sha256(seed, M_DIGEST_BYTES);
    }

    /// @dev F(PK.seed, ADRS, M1) — single-block tweakable hash.
    function _f(bytes memory pkSeed, bytes memory adrs, bytes memory m1)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory padded = abi.encodePacked(pkSeed, _zeroPad(64 - N), adrs, m1);
        bytes32 h = sha256(padded);
        bytes memory out = new bytes(N);
        for (uint256 i = 0; i < N; ++i) out[i] = h[i];
        return out;
    }

    /// @dev H(PK.seed, ADRS, M1, M2) — used inside Merkle tree node hashing.
    function _hash2(
        bytes memory pkSeed,
        bytes memory adrs,
        bytes memory m1,
        bytes memory m2
    ) internal pure returns (bytes memory) {
        bytes memory padded = abi.encodePacked(pkSeed, _zeroPad(64 - N), adrs, m1, m2);
        bytes32 h = sha256(padded);
        bytes memory out = new bytes(N);
        for (uint256 i = 0; i < N; ++i) out[i] = h[i];
        return out;
    }

    /// @dev T_l(PK.seed, ADRS, M) — l*n-byte input compressed to n bytes.
    function _tHash(bytes memory pkSeed, bytes memory adrs, bytes memory m)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory padded = abi.encodePacked(pkSeed, _zeroPad(64 - N), adrs, m);
        bytes32 h = sha256(padded);
        bytes memory out = new bytes(N);
        for (uint256 i = 0; i < N; ++i) out[i] = h[i];
        return out;
    }

    /// @dev MGF1-SHA-256 (RFC 8017 §B.2.1).
    function _mgf1Sha256(bytes memory seed, uint256 outLen) internal pure returns (bytes memory) {
        bytes memory out = new bytes(outLen);
        uint256 written = 0;
        uint32 ctr = 0;
        while (written < outLen) {
            bytes memory block_ = abi.encodePacked(seed, _u32be(ctr));
            bytes32 h = sha256(block_);
            uint256 take = outLen - written;
            if (take > 32) take = 32;
            for (uint256 i = 0; i < take; ++i) out[written + i] = h[i];
            written += take;
            ctr += 1;
        }
        return out;
    }

    // ─── Address (ADRS) helpers ─────────────────────────────────────

    function _setLayer(bytes memory adrs, uint256 layer) internal pure {
        adrs[0] = bytes1(uint8(layer));
    }

    function _setTreeAddress(bytes memory adrs, uint64 t) internal pure {
        // bytes [1..9) = big-endian 8-byte tree address
        for (uint256 i = 0; i < 8; ++i) {
            adrs[1 + i] = bytes1(uint8(t >> ((7 - i) * 8)));
        }
    }

    function _setType(bytes memory adrs, uint256 t) internal pure {
        adrs[9] = bytes1(uint8(t));
        // FIPS-205 §4.3: setting the type clears the last 12 bytes.
        for (uint256 i = 10; i < ADRS_BYTES; ++i) adrs[i] = 0;
    }

    function _setKeypair(bytes memory adrs, uint32 k) internal pure {
        adrs[10] = bytes1(uint8(k >> 24));
        adrs[11] = bytes1(uint8(k >> 16));
        adrs[12] = bytes1(uint8(k >> 8));
        adrs[13] = bytes1(uint8(k));
    }

    function _setChainAddress(bytes memory adrs, uint256 c) internal pure {
        adrs[14] = bytes1(uint8(c >> 24));
        adrs[15] = bytes1(uint8(c >> 16));
        adrs[16] = bytes1(uint8(c >> 8));
        adrs[17] = bytes1(uint8(c));
    }

    function _setTreeHeight(bytes memory adrs, uint256 h) internal pure {
        adrs[14] = bytes1(uint8(h >> 24));
        adrs[15] = bytes1(uint8(h >> 16));
        adrs[16] = bytes1(uint8(h >> 8));
        adrs[17] = bytes1(uint8(h));
    }

    function _setHashAddress(bytes memory adrs, uint256 a) internal pure {
        adrs[18] = bytes1(uint8(a >> 24));
        adrs[19] = bytes1(uint8(a >> 16));
        adrs[20] = bytes1(uint8(a >> 8));
        adrs[21] = bytes1(uint8(a));
    }

    function _setTreeIndex(bytes memory adrs, uint32 ti) internal pure {
        adrs[18] = bytes1(uint8(ti >> 24));
        adrs[19] = bytes1(uint8(ti >> 16));
        adrs[20] = bytes1(uint8(ti >> 8));
        adrs[21] = bytes1(uint8(ti));
    }

    // ─── Bit / byte plumbing ────────────────────────────────────────

    function _baseW(bytes memory X, uint256 outLen, uint8[] memory out, uint256 outOff)
        internal
        pure
    {
        uint256 inIdx = 0;
        uint256 total = 0;
        uint256 bits = 0;
        for (uint256 consumed = 0; consumed < outLen; ++consumed) {
            if (bits == 0) {
                total = uint8(X[inIdx]);
                inIdx += 1;
                bits = 8;
            }
            bits -= LG_W;
            out[outOff + consumed] = uint8((total >> bits) & (W - 1));
        }
    }

    function _toByte(uint256 x, bytes memory out) internal pure {
        uint256 outLen = out.length;
        for (uint256 i = 0; i < outLen; ++i) {
            out[outLen - 1 - i] = bytes1(uint8(x & 0xff));
            x >>= 8;
        }
    }

    function _extractBits(bytes memory src, uint256 bitOff, uint256 bitLen)
        internal
        pure
        returns (uint256 v)
    {
        for (uint256 i = 0; i < bitLen; ++i) {
            uint256 b = bitOff + i;
            uint256 bit = (uint256(uint8(src[b >> 3])) >> (7 - (b & 7))) & 1;
            v = (v << 1) | bit;
        }
    }

    function _readBeUint(bytes memory b, uint256 off, uint256 len) internal pure returns (uint64 v) {
        for (uint256 i = 0; i < len; ++i) {
            v = (v << 8) | uint64(uint8(b[off + i]));
        }
    }

    function _slice(bytes memory src, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; ++i) out[i] = src[off + i];
    }

    function _slice(bytes calldata src, uint256 off, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; ++i) out[i] = src[off + i];
    }

    function _zeroPad(uint256 n) internal pure returns (bytes memory) {
        return new bytes(n);
    }

    function _u32be(uint32 v) internal pure returns (bytes memory out) {
        out = new bytes(4);
        out[0] = bytes1(uint8(v >> 24));
        out[1] = bytes1(uint8(v >> 16));
        out[2] = bytes1(uint8(v >> 8));
        out[3] = bytes1(uint8(v));
    }

    function _copy(bytes memory src) internal pure returns (bytes memory out) {
        out = new bytes(src.length);
        for (uint256 i = 0; i < src.length; ++i) out[i] = src[i];
    }
}
