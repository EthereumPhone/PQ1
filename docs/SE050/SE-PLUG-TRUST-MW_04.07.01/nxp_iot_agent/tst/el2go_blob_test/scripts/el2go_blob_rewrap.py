#!/usr/bin/env python3
# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0

import pathlib
import subprocess
import argparse
import json
import base64
import os
import shutil
import sys
import time
import datetime

parser = argparse.ArgumentParser(description='Rewraps EL2GO Secure Objects for N10 based devices')

parser.add_argument('rtp_json_path', type=pathlib.Path, help='Path to a JSON file containing raw EL2GO RTP objects')
parser.add_argument('provisioning_fw_path', type=pathlib.Path, help='Path to the provisioning firmware SB3 container')
parser.add_argument('com_port', type=str, help='The COM port to use for contacting the device in ISP mode')
parser.add_argument('rewrapped_rtp_json_out_path', type=pathlib.Path, help='Output path for the JSON file containing the rewrapped EL2GO objects')

args = parser.parse_args()

if not args.rtp_json_path.is_file():
    parser.error("No file found at rtp_json_path")

if not args.provisioning_fw_path.is_file():
    parser.error("No file found at provisioning_fw_path")

workspace = pathlib.Path(os.path.abspath(os.path.dirname(__file__))).joinpath("workspace")

unprocessed_blobs_path = workspace.joinpath("unprocessed_blobs.json")
processed_blobs_path = workspace.joinpath("processed_blobs.json")
user_config_path = workspace.joinpath("user_config.bin")
raw_blobs_path = workspace.joinpath("raw_blobs.bin")
wrapped_blobs_path = workspace.joinpath("wrapped_blobs.bin")

user_config = b'\x45\x4C\x55\x43\x00\x01\x00\x20\x00\x00\x1C\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
blhost_args = ["blhost", "-p", f"{args.com_port},115200", "--"]

def wrap_blobs(raw_blobs) -> bytes:
    with open(user_config_path, "wb") as user_config_file:
        user_config_file.write(user_config)

    with open(raw_blobs_path, "wb") as raw_blobs_file:
        raw_blobs_file.write(raw_blobs)

    subprocess.run(["nxpdebugmbox", "ispmode", "-m", "1"], check=True)

    subprocess.run(blhost_args + ["write-memory", "0x20000000", user_config_path], check=True)
    subprocess.run(blhost_args + ["write-memory", "0x20000100", raw_blobs_path], check=True)
    subprocess.run(blhost_args + ["receive-sb-file", args.provisioning_fw_path], check=True)

    time.sleep(3)

    subprocess.run(["nxpdebugmbox", "ispmode", "-m", "1"], check=True)

    subprocess.run(blhost_args + ["read-memory", "0x1C0000", hex(blobs_total_size), wrapped_blobs_path], check=True)

    with open(wrapped_blobs_path, "rb") as wrapped_blobs_file:
        wrapped_blobs = wrapped_blobs_file.read()

    os.remove(user_config_path)
    os.remove(raw_blobs_path)
    os.remove(wrapped_blobs_path)

    return wrapped_blobs

if unprocessed_blobs_path.is_file():
    filetime = datetime.datetime.fromtimestamp(os.path.getmtime(unprocessed_blobs_path))
    sys.stdout.write(f"Continue with remaining unprocessed blobs from last run ({filetime.isoformat()})? [Y/n] ")
    if input().lower() not in ["y", ""]:
        shutil.rmtree(workspace)

if not unprocessed_blobs_path.is_file():
    if workspace.is_dir():
        shutil.rmtree(workspace)
    workspace.mkdir()

    with open(args.rtp_json_path) as rtp_json_file:
        rtp_json = json.load(rtp_json_file)

    device = rtp_json[0]

    previous_count = len(device['rtpProvisionings'])
    device['rtpProvisionings'] = list(filter(lambda prov: prov['state'] == "GENERATION_COMPLETED", device['rtpProvisionings']))
    diff_count = previous_count - len(device['rtpProvisionings'])
    if diff_count:
        print(f"Ignoring {diff_count} blobs that failed to generate")

    previous_count = len(device['rtpProvisionings'])
    device['rtpProvisionings'] = list(filter(lambda prov: prov['secureObject']['type'] != "OEM_FW_AUTH_KEY_HASH" and prov['secureObject']['type'] != "OEM_FW_DECRYPT_KEY", device['rtpProvisionings']))
    diff_count = previous_count - len(device['rtpProvisionings'])
    if diff_count:
        print(f"Ignoring OEM_FW_AUTH_KEY_HASH and OEM_FW_DECRYPT_KEY (device needs to be provisioned already)")

    with open(unprocessed_blobs_path, "w") as unprocessed_blobs_file:
        json.dump([device], unprocessed_blobs_file, indent=4)

while True:
    with open(unprocessed_blobs_path) as unprocessed_blobs_file:
        unprocessed_blobs = json.load(unprocessed_blobs_file)

    device = unprocessed_blobs[0]

    blobs = []
    blobs_total_size = 0
    for provisioning in device['rtpProvisionings']:
        base64_string = provisioning['apdus']['createApdu']['apdu']
        blob = base64.b64decode(base64_string)

        if len(blobs) + 1 <= 16 and blobs_total_size + len(blob) <= 16384:
            blobs.append(blob)
            blobs_total_size += len(blob)
        else: 
            break

    print(f"Rewrapping batch of {len(blobs)} blobs totalling {blobs_total_size} bytes")
    wrapped_blobs = wrap_blobs(b"".join(blobs))

    current_byte = 0
    for index, provisioning in enumerate(device['rtpProvisionings'][:len(blobs)]):
        blob_len = len(blobs[index])
        wrapped_blob = wrapped_blobs[current_byte:current_byte + blob_len]
        provisioning['apdus']['createApdu']['apdu'] = base64.b64encode(wrapped_blob).decode('ascii')
        current_byte += len(blobs[index])

    processed = device['rtpProvisionings'][:len(blobs)]
    unprocessed = device['rtpProvisionings'][len(blobs):]

    if processed_blobs_path.is_file():
        with open(processed_blobs_path) as processed_blobs_file:
            processed_blobs = json.load(processed_blobs_file)

        device = processed_blobs[0]
        device['rtpProvisionings'] += processed
    else:
        device['rtpProvisionings'] = processed

    with open(processed_blobs_path, "w") as processed_blobs_file:
        json.dump([device], processed_blobs_file, indent=4)

    if len(unprocessed):
        device['rtpProvisionings'] = unprocessed

        with open(unprocessed_blobs_path, "w") as unprocessed_blobs_file:
            json.dump([device], unprocessed_blobs_file, indent=4)
    else:
        os.remove(unprocessed_blobs_path)
        os.replace(processed_blobs_path, args.rewrapped_rtp_json_out_path)
        workspace.rmdir()
        print(f"Successfully rewrapped {len(device['rtpProvisionings'])} blobs for device UUID {device['deviceId']}")
        break
