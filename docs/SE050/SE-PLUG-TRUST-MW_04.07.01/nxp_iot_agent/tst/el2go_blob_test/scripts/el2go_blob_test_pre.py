#!/usr/bin/env python3
# Copyright 2024-2025 NXP
# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import json
import base64
import datetime
import pathlib

parser = argparse.ArgumentParser(description='Converts EL2GO RTP JSON for the el2go_blob_test framework')

parser.add_argument('rtp_json_path', type=pathlib.Path, help='Path to a JSON file containing RTP objects')
parser.add_argument('--object_type', type=str, choices=['psa', 'apdu'], default="psa", help='The type of the RTP objects')
parser.add_argument('--storage_mode', type=str, choices=['inline', 'memory', 'filesystem'], default="inline", help='The way in which the blobs should be stored and referenced')
parser.add_argument('--blob_address', type=lambda x: int(x, 0), help='The starting address in memory where the blobs are stored on device')
parser.add_argument('--partition', type=str, default="1/1", help='The way the RTP objects should be split (current part/total parts)')

args = parser.parse_args()

if not args.rtp_json_path.is_file():
    parser.error("No file found at rtp_json_path")

if args.storage_mode == "memory" and not args.blob_address:
    parser.error("blob_address needs to be specified when using storage_mode memory")

if args.object_type != "psa" or (args.storage_mode != "inline" and args.storage_mode != "memory"):
    parser.error("Currently only PSA RTP objects in inline or memory mode are supported")

partitions = args.partition.split("/")
if len(partitions) != 2 or not partitions[0].isdigit() or not partitions[1].isdigit() \
   or int(partitions[0]) == 0 or int(partitions[1]) == 0 or int(partitions[0]) > int(partitions[1]):
    parser.error("Invalid partition format")

work_dir_path = pathlib.Path(os.path.abspath(os.path.dirname(__file__)))
inc_path = work_dir_path.parent.joinpath("inc")
el2go_blob_test_generic_header_path = inc_path.joinpath("el2go_blob_test_suite_generic.h")
if not el2go_blob_test_generic_header_path.exists():
    el2go_blob_test_generic_header_path = work_dir_path.parent.joinpath("el2go_blob_test_suite_generic.h")

def parse_bytes_tlv(data: bytes, tag_size: int = 1) -> dict[int, int]:
    result = {}

    default_length = 1
    next_addr = 0
    while True:
        tag = int.from_bytes(data[next_addr:next_addr+tag_size], "big")

        length_bytes = default_length
        temp = (next_addr + tag_size + default_length)
        length = int.from_bytes(data[next_addr+tag_size:temp], "big")
        
        if(length > 128):
            length_bytes = (length & 0x0f)
            length = int.from_bytes(data[temp:temp+length_bytes], "big")

        val_addr = (temp + length_bytes - default_length)
        next_addr = (val_addr + length)

        if(length > 0):
            value = data[val_addr:next_addr]
            result[tag] = value

        if(next_addr >= len(data)):
            break

    return result

def array_split(lst: list, parts: int) -> list:
    length = len(lst)
    if(length <= 0):
        return []

    if(parts <= 0):
        raise ValueError("There must be more than 0 parts!")
    elif(length < parts):
        raise ValueError("There must be less parts than items in the list!")

    
    from math import ceil
    steps = [ceil(length / parts)] * parts
    for i in range(0, parts):
        if(sum(steps) == length):
            break
        steps[parts - i - 1] -= 1

    i = 0
    result = []
    for step in steps:
        result += [lst[i:i+step]]
        i = i + step

    return result

def get_usage(usage):
    flags = []
    if usage == 0x00000000:
        flags.append("NONE")
    else:
        if usage & 0x00000001:
            flags.append("EXPORT")
        if usage & 0x00000100 and usage & 0x00000200:
            flags.append("CRYPT")
        elif usage & 0x00000100:
            flags.append("ENCRYPT")
        elif usage & 0x00000200:
            flags.append("DECRYPT")
        if  usage & 0x00000400 and usage & 0x00000800:
            flags.append("SIGVERMSG")
        elif usage & 0x00000400:
            flags.append("SIGMSG")
        elif usage & 0x00000800:
            flags.append("VERMSG")
        if usage & 0x00001000 and usage & 0x00002000:
            flags.append("SIGVERHASH")
        elif usage & 0x00001000:
            flags.append("SIGHASH")
        elif usage & 0x00002000:
            flags.append("VERHASH")
        if usage & 0x00004000:
            flags.append("DERIVE")
    if len(flags):
        return "+".join(flags)
    else:
        return "UNKNOWN"

def get_hash(hash):
    if(hash == 0x02000005):
        return "SHA1"
    elif(hash == 0x02000008):
        return "SHA224"
    elif(hash == 0x02000009):
        return "SHA256"
    elif(hash == 0x0200000a):
        return "SHA384"
    elif(hash == 0x0200000b):
        return "SHA512"
    elif(hash == 0x0200000c):
        return "SHA512224"
    elif(hash == 0x0200000d):
        return "SHA512256"
    elif(hash == 0x020000ff):
        return "ANYHASH"
    else:
        return "UNKNOWN"

def get_algorithm(algorithm):
    if(algorithm == 0x00000000):
        return "NONE"
    elif(algorithm == 0x03c00200):
        return "CMAC"
    elif(algorithm == 0x04c01000):
        return "CTR"
    elif(algorithm == 0x04404400):
        return "ECB"
    elif(algorithm == 0x04404000):
        return "CBC"
    elif(algorithm == 0x05500200):
        return "GCM"
    elif(algorithm == 0x06000200):
        return "RAW"
    elif(algorithm == 0x06000600):
        return "ECDSAANY"
    elif(algorithm == 0x07000200):
        return "PKCS1V15"
    elif(algorithm == 0x09020000):
        return "ECDH"
    elif(algorithm == 0x84C0FF00):
        return "ALL_CIPHER"
    elif(algorithm == 0x8550FF00):
        return "ALL_AEAD"
    elif(algorithm == 0x8902FC00):
        return "S200_ECDH_OR_ECDH_CKDF"
    elif(algorithm == 0x8800FD00):
        return "S200_ECBKDF_OR_CKDF"
    elif(algorithm == 0x8800FF00):
        return "ALG_S50_CKDF"        
    elif(algorithm == 0x8800FE09):
        return "ALG_S50_HKDF_SHA_256"         
    else:
        hash_string = get_hash(0x02000000 | (algorithm & 0x000000ff))
        algorithm = algorithm & ~0x000000ff

        if(algorithm == 0x03800000):
            return "HMAC" + hash_string
        elif(algorithm == 0x06000200):
            return "PKCS1V15" + hash_string
        elif(algorithm == 0x06000300):
            return "PSS" + hash_string
        elif(algorithm == 0x06000600):
            return "ECDSA" + hash_string
        elif(algorithm == 0x07000300):
            return "OAEP" + hash_string
        elif(algorithm == 0x08000100):
            return "HKDF" + hash_string
        else:
            return "UNKNOWN"

def data_to_c_array(name, data):
    return f"static const uint8_t {name}[] = {{{', '.join([hex(byte) for byte in data])}}};"

def get_description(internal, obj_class, obj_type, usage, algorithm):
    obj_type = obj_type.replace("_", "")
    return f"{'Internal' if internal else 'External'} {obj_class} {obj_type} {get_usage(usage)} {get_algorithm(algorithm)}"

def get_test_entry_memory(index, description, address, size):
    return f"    {{NULL, \"EL2GO_BLOB_TEST_GENERIC_{index}\", \"{description}\", (uint8_t *){hex(address)}, {size}}},"

def get_test_entry(index, description, name):
    return f"    {{NULL, \"EL2GO_BLOB_TEST_GENERIC_{index}\", \"{description}\", {name}, sizeof({name})}},"

with open(args.rtp_json_path) as rtp_json_file:
    rtp_json = json.load(rtp_json_file)

device = rtp_json[0]

previous_count = len(device['rtpProvisionings'])
device['rtpProvisionings'] = list(filter(lambda prov: prov['state'] == "GENERATION_COMPLETED", device['rtpProvisionings']))
diff_count = previous_count - len(device['rtpProvisionings'])
if diff_count:
    print(f"Ignoring {diff_count} blobs that failed to generate")

if int(partitions[1]) > 1:
    print(f"Splitting into {int(partitions[1])} parts ({args.partition})")
    provisioning_parts = array_split(device['rtpProvisionings'], int(partitions[1]))
    device['rtpProvisionings'] = provisioning_parts[int(partitions[0]) - 1]

data_arrays = []
test_entries = []

if args.storage_mode == "memory":
    current_blob_address = args.blob_address
    data_arrays.append(f"// Blobs are stored in memory starting at {hex(current_blob_address)}")

for provisioning in device['rtpProvisionings']:
    base64_string = provisioning['apdus']['createApdu']['apdu']
    blob = base64.b64decode(base64_string)

    blob_tlv = parse_bytes_tlv(blob)

    internal = int.from_bytes(blob_tlv[0x46], "big") == 0xE0000101
    bits = int.from_bytes(blob_tlv[0x45], "big")
    usage = int.from_bytes(blob_tlv[0x43], "big")
    algorithm = int.from_bytes(blob_tlv[0x42], "big")

    obj_class = provisioning['secureObject']['type']
    if 'algorithm' in provisioning['secureObject']:
        obj_type = provisioning['secureObject']['algorithm']
    elif 'algorithmType' in provisioning['secureObject']:
        obj_type = provisioning['secureObject']['algorithmType'] + str(int(bits))
    else:
        obj_type = str(int(bits / 8)) + 'B'

    if obj_type == "OEM_FW_AUTH_KEY_HASH" or obj_type == "OEM_FW_DECRYPT_KEY":
        print(f"Ignoring {obj_type} (not PSA compliant)")
        continue
    elif obj_class == "BINARY_FILE" and usage == 0x00 and algorithm == 0x00:
        print(f"Ignoring OTP/IFR BINARY_FILE (not PSA compliant)")
        continue

    number = provisioning['secureObject']['objectId']
    name = f"{obj_class}_{obj_type}_{provisioning['secureObject']['objectId']}_{provisioning['secureObject']['id']}"
    description = get_description(internal, obj_class, obj_type, usage, algorithm)

    if args.storage_mode == "memory":
        test_entries.append(get_test_entry_memory(number, description, current_blob_address, len(blob)))
        current_blob_address += len(blob)
    else:
        data_arrays.append(data_to_c_array(name, blob))
        test_entries.append(get_test_entry(number, description, name))

el2go_blob_test_generic_header=f"""/*
 * Copyright {datetime.date.today().year} NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_BLOB_TEST_SUITE_GENERIC_H__
#define __EL2GO_BLOB_TEST_SUITE_GENERIC_H__

#ifdef __cplusplus
extern \"C\" {{
#endif

#include "el2go_blob_test.h"

// Generated for UUID {device['deviceId']}

{chr(10).join(sorted(data_arrays))}

static struct test_t blob_generic_tests[] = {{
{chr(10).join(sorted(test_entries))}
}};

#ifdef __cplusplus
}}
#endif

#endif /* __EL2GO_BLOB_TEST_SUITE_GENERIC_H__ */
"""

el2go_blob_test_generic_header_path.write_text(el2go_blob_test_generic_header)

print(f"Successfully processed {len(test_entries)} blobs for device UUID {device['deviceId']}")
