#!/usr/bin/env python3
"""
ABI-encode handleOps calldata and output it for cast send --data.
"""
import json, struct

def pad32(val):
    if isinstance(val, int):
        return val.to_bytes(32, "big")
    if isinstance(val, bytes):
        return bytes(32 - len(val)) + val
    raise TypeError(f"Cannot pad32 {type(val)}")

def encode_bytes(data: bytes) -> bytes:
    """ABI-encode a dynamic bytes field (length + padded data)."""
    padded = data + bytes((-len(data)) % 32)
    return pad32(len(data)) + padded

def encode_userop(d) -> bytes:
    """ABI-encode a UserOperation struct for handleOps."""
    sender = bytes.fromhex(d["sender"][2:])
    nonce = d["nonce"]
    init_code = bytes.fromhex(d["initCode"][2:]) if d["initCode"] != "0x" else b""
    call_data = bytes.fromhex(d["callData"][2:])
    call_gas_limit = d["callGasLimit"]
    verification_gas_limit = d["verificationGasLimit"]
    pre_verification_gas = d["preVerificationGas"]
    max_fee_per_gas = d["maxFeePerGas"]
    max_priority_fee_per_gas = d["maxPriorityFeePerGas"]
    paymaster_and_data = bytes.fromhex(d["paymasterAndData"][2:]) if d["paymasterAndData"] != "0x" else b""
    signature = bytes.fromhex(d["signature"][2:])

    # UserOperation is a struct with 3 dynamic fields: initCode, callData, paymasterAndData, signature
    # Layout: 11 fields, 4 dynamic (initCode, callData, paymasterAndData, signature)
    # Static fields are in-place, dynamic fields have offsets

    # Offsets: 11 * 32 = 352 bytes of head
    head_size = 11 * 32

    # Build dynamic parts
    init_code_encoded = encode_bytes(init_code)
    call_data_encoded = encode_bytes(call_data)
    paymaster_encoded = encode_bytes(paymaster_and_data)
    sig_encoded = encode_bytes(signature)

    # Calculate offsets for dynamic fields
    # initCode offset (field 2): head_size
    init_code_offset = head_size
    # callData offset (field 3): init_code_offset + len(init_code_encoded)
    call_data_offset = init_code_offset + len(init_code_encoded)
    # paymasterAndData offset (field 9): call_data_offset + len(call_data_encoded)
    paymaster_offset = call_data_offset + len(call_data_encoded)
    # signature offset (field 10): paymaster_offset + len(paymaster_encoded)
    sig_offset = paymaster_offset + len(paymaster_encoded)

    head = (
        pad32(sender) +                    # 0: sender
        pad32(nonce) +                      # 1: nonce
        pad32(init_code_offset) +           # 2: initCode offset
        pad32(call_data_offset) +           # 3: callData offset
        pad32(call_gas_limit) +             # 4: callGasLimit
        pad32(verification_gas_limit) +     # 5: verificationGasLimit
        pad32(pre_verification_gas) +       # 6: preVerificationGas
        pad32(max_fee_per_gas) +            # 7: maxFeePerGas
        pad32(max_priority_fee_per_gas) +   # 8: maxPriorityFeePerGas
        pad32(paymaster_offset) +           # 9: paymasterAndData offset
        pad32(sig_offset)                   # 10: signature offset
    )

    return head + init_code_encoded + call_data_encoded + paymaster_encoded + sig_encoded


def main():
    d = json.load(open("/tmp/e2e_output2.json"))
    beneficiary = bytes.fromhex("8796E8092FCD6F0439daA99E6b41adb8f0199cD4")

    # handleOps selector
    from Crypto.Hash import keccak as _keccak_mod
    h = _keccak_mod.new(digest_bits=256)
    h.update(b"handleOps((address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[],address)")
    selector = h.digest()[:4]

    # ABI encode: handleOps(UserOperation[], address)
    # Head: offset to array (64), beneficiary
    # Array: length (1), offset to element (32), element data

    userop_encoded = encode_userop(d)

    # The array is a dynamic type, so we have:
    # [0..31] offset to ops array = 64
    # [32..63] beneficiary (address, padded)
    # [64..95] array length = 1
    # [96..127] offset to first element = 32
    # [128..] first element data

    calldata = (
        selector +
        pad32(64) +                     # offset to UserOperation[]
        pad32(beneficiary) +            # beneficiary address
        pad32(1) +                      # array length = 1
        pad32(32) +                     # offset to first element
        userop_encoded                  # the UserOperation struct
    )

    print("0x" + calldata.hex())


if __name__ == "__main__":
    main()
