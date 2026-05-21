/-
ERC-7201 / ERC-1967 storage-slot disjointness.

The `PQSmartWallet` proxy uses three storage regions:
  * ERC-1967 IMPLEMENTATION_SLOT (the proxy's current impl address).
  * ERC-1967 ADMIN_SLOT (the proxy's admin, unused in our UUPS-less
    design but still part of the ERC-1967 reserved set).
  * ERC-7201 namespaced storage at
    `keccak256(abi.encode(uint256(keccak256("pqsigner.storage.PQMultiOwnable")) - 1)) & ~bytes32(0xff)`
    where `PQMultiOwnable` data lives.

Claim 2 (owner-set integrity) requires these regions to be disjoint —
if the namespace slot collided with the impl slot, a malicious owner
mutation could overwrite the impl pointer and bypass the
`SelfCallForbidden` upgrade guard. Stated as kernel-decidable
inequalities on the three `ByteVec 32` literals.

These constants are parity-tested against the Solidity literal at
`PQMultiOwnable.sol:64` and the standard ERC-1967 slot constants by
`test/StorageSlotParity.t.sol`; any future change to either side
fails CI.
-/

import SphincsCVerify.Spec.Bytes

namespace SphincsCVerify.Wallet.StorageLayout

open SphincsCVerify.Spec

/-- ERC-7201 namespace slot for `pqsigner.storage.PQMultiOwnable`.
    Pinned to the Solidity literal at `PQMultiOwnable.sol:64`:
    `0x470749eea5ac4a541d6582e535445f94e7300bac9e0e4e5577fd3336b407d000`. -/
def PQ_MULTI_OWNABLE_STORAGE_SLOT : ByteVec 32 :=
  ⟨#[0x47, 0x07, 0x49, 0xee, 0xa5, 0xac, 0x4a, 0x54,
     0x1d, 0x65, 0x82, 0xe5, 0x35, 0x44, 0x5f, 0x94,
     0xe7, 0x30, 0x0b, 0xac, 0x9e, 0x0e, 0x4e, 0x55,
     0x77, 0xfd, 0x33, 0x36, 0xb4, 0x07, 0xd0, 0x00],
   by decide⟩

/-- Standard ERC-1967 implementation slot:
    `keccak256("eip1967.proxy.implementation") - 1
       = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc`. -/
def ERC1967_IMPLEMENTATION_SLOT : ByteVec 32 :=
  ⟨#[0x36, 0x08, 0x94, 0xa1, 0x3b, 0xa1, 0xa3, 0x21,
     0x06, 0x67, 0xc8, 0x28, 0x49, 0x2d, 0xb9, 0x8d,
     0xca, 0x3e, 0x20, 0x76, 0xcc, 0x37, 0x35, 0xa9,
     0x20, 0xa3, 0xca, 0x50, 0x5d, 0x38, 0x2b, 0xbc],
   by decide⟩

/-- Standard ERC-1967 admin slot:
    `keccak256("eip1967.proxy.admin") - 1
       = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103`. -/
def ERC1967_ADMIN_SLOT : ByteVec 32 :=
  ⟨#[0xb5, 0x31, 0x27, 0x68, 0x4a, 0x56, 0x8b, 0x31,
     0x73, 0xae, 0x13, 0xb9, 0xf8, 0xa6, 0x01, 0x6e,
     0x24, 0x3e, 0x63, 0xb6, 0xe8, 0xee, 0x11, 0x78,
     0xd6, 0xa7, 0x17, 0x85, 0x0b, 0x5d, 0x61, 0x03],
   by decide⟩

/-- Standard ERC-1967 beacon slot:
    `keccak256("eip1967.proxy.beacon") - 1
       = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50`. -/
def ERC1967_BEACON_SLOT : ByteVec 32 :=
  ⟨#[0xa3, 0xf0, 0xad, 0x74, 0xe5, 0x42, 0x3a, 0xeb,
     0xfd, 0x80, 0xd3, 0xef, 0x43, 0x46, 0x57, 0x83,
     0x35, 0xa9, 0xa7, 0x2a, 0xea, 0xee, 0x59, 0xff,
     0x6c, 0xb3, 0x58, 0x2b, 0x35, 0x13, 0x3d, 0x50],
   by decide⟩

/-! ## Disjointness theorems

These are kernel-decided inequalities — the ByteVec literals are
distinct at the first non-matching byte, so `decide` reduces each one
to `true`. -/

/-- The PQ namespace slot and the ERC-1967 implementation slot are
    disjoint. A reachable storage write to the namespace slot
    therefore cannot corrupt the implementation pointer. -/
theorem pq_storage_disjoint_from_erc1967_impl :
    PQ_MULTI_OWNABLE_STORAGE_SLOT ≠ ERC1967_IMPLEMENTATION_SLOT := by decide

/-- The PQ namespace slot and the ERC-1967 admin slot are disjoint. -/
theorem pq_storage_disjoint_from_erc1967_admin :
    PQ_MULTI_OWNABLE_STORAGE_SLOT ≠ ERC1967_ADMIN_SLOT := by decide

/-- The PQ namespace slot and the ERC-1967 beacon slot are disjoint. -/
theorem pq_storage_disjoint_from_erc1967_beacon :
    PQ_MULTI_OWNABLE_STORAGE_SLOT ≠ ERC1967_BEACON_SLOT := by decide

/-- The three ERC-1967 reserved slots are pairwise disjoint. -/
theorem erc1967_impl_disjoint_from_admin :
    ERC1967_IMPLEMENTATION_SLOT ≠ ERC1967_ADMIN_SLOT := by decide

theorem erc1967_impl_disjoint_from_beacon :
    ERC1967_IMPLEMENTATION_SLOT ≠ ERC1967_BEACON_SLOT := by decide

theorem erc1967_admin_disjoint_from_beacon :
    ERC1967_ADMIN_SLOT ≠ ERC1967_BEACON_SLOT := by decide

end SphincsCVerify.Wallet.StorageLayout
