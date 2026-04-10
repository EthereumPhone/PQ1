#! python3

# Copyright(C) NXP B.V. 2020
#
#  All rights are reserved. Reproduction in whole or in part is prohibited
#  without the prior written consent of the copy-right owner.
#  This source code and any compilation or derivative thereof is the sole
#  property of NXP B.V. and is provided pursuant to a Software License
#  Agreement. This code is the proprietary information of NXP B.V. and
#  is confidential in nature. Its use and dissemination by any party other
#  than NXP B.V. is strictly limited by the confidential information
#  provisions of the agreement referenced above.


import json
from typing import List
import argparse
import pathlib
from schema import MulticastPackage_1_2
from schema import MulticastPackage_1_3
from sems_lite_utils import SignatureParser
import sys

class Config_1_2:
    def __init__(self,
                 Copyright: str,
                 TargetCommercialName: str,
                 TargetEntityID: str,
                 Target12nc: str,
                 requiredFreeBytesNonVolatileMemory: int,
                 requiredFreeBytesTransientMemory: int,
                 MulticastPackageName: str,
                 MulticastPackageDescription: str,
                 SubComponentMetaData: List[MulticastPackage_1_2.SubComponentMetaDataType],
                 MulticastPackageVersion: str):
        self.Copyright = Copyright
        self.TargetCommercialName = TargetCommercialName
        self.Target12nc = Target12nc
        self.TargetEntityID = TargetEntityID
        self.requiredFreeBytesNonVolatileMemory = requiredFreeBytesNonVolatileMemory
        self.requiredFreeBytesTransientMemory = requiredFreeBytesTransientMemory
        self.MulticastPackageName = MulticastPackageName
        self.MulticastPackageDescription = MulticastPackageDescription
        self.SubComponentMetaData = SubComponentMetaData
        self.MulticastPackageVersion = MulticastPackageVersion

    @staticmethod
    def from_file(json_file_path):
        with open(json_file_path, 'r') as config_json_file:
            data = json.loads(config_json_file.read())
            obj = Config_1_2(**data)
            obj.SubComponentMetaData = list(map(MulticastPackage_1_2.SubComponentMetaDataType.from_json, data["SubComponentMetaData"]))
            return obj

class Config_1_3:
    def __init__(self,
                 Copyright: str,
                 TargetCommercialName: str,
                 TargetEntityID: str,
                 Target12nc: str,
                 requiredFreeBytesNonVolatileMemory: int,
                 requiredFreeBytesTransientMemory: int,
                 MulticastPackageName: str,
                 MulticastPackageDescription: str,
                 SubComponentMetaData: List[MulticastPackage_1_3.SubComponentMetaDataType],
                 MulticastPackageVersion: str,
                 PkSemsCaAut: str):
        self.Copyright = Copyright
        self.TargetCommercialName = TargetCommercialName
        self.Target12nc = Target12nc
        self.TargetEntityID = TargetEntityID
        self.requiredFreeBytesNonVolatileMemory = requiredFreeBytesNonVolatileMemory
        self.requiredFreeBytesTransientMemory = requiredFreeBytesTransientMemory
        self.MulticastPackageName = MulticastPackageName
        self.MulticastPackageDescription = MulticastPackageDescription
        self.SubComponentMetaData = SubComponentMetaData
        self.MulticastPackageVersion = MulticastPackageVersion
        self.PkSemsCaAut = PkSemsCaAut

    @staticmethod
    def from_file(json_file_path):
        with open(json_file_path, 'r') as config_json_file:
            data = json.loads(config_json_file.read())
            obj = Config_1_3(**data)
            obj.SubComponentMetaData = list(map(MulticastPackage_1_3.SubComponentMetaDataType.from_json, data["SubComponentMetaData"]))
            return obj

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pkg_format', required=True, nargs="?", choices=['1.2', '1.3'], help="1.2 or 1.3.")
    parser.add_argument('--config_file', required=True, nargs="?", help="Config File for MulticastPackage generation.")
    parser.add_argument('--script_file', required=True, nargs="?", help="Encrypted and Signed script as output by the ls-cgt tool.")
    parser.add_argument('--out', required=True, nargs="?", help="Output MulticastPackage json file.")
    args = parser.parse_args()

    pkg_format = args.pkg_format

    if (pkg_format == "1.2"):
        config = Config_1_2.from_file(args.config_file)
    else:
        config = Config_1_3.from_file(args.config_file)

    with open(args.script_file, 'r') as script_file:
        if (pkg_format == "1.2"):
            multicast_package = MulticastPackage_1_2.MulticastPackage.create(
                Copyright=config.Copyright,
                TargetCommercialName=config.TargetCommercialName,
                Target12nc=config.Target12nc,
                TargetEntityID=config.TargetEntityID,
                requiredFreeBytesNonVolatileMemory=config.requiredFreeBytesNonVolatileMemory,
                requiredFreeBytesTransientMemory=config.requiredFreeBytesTransientMemory,
                MulticastPackageName=config.MulticastPackageName,
                MulticastPackageDescription=config.MulticastPackageDescription,
                SubComponentMetaData=config.SubComponentMetaData,
                SignatureOverCommands=SignatureParser.SignatureParser.get_signature(args.script_file),
                MulticastCommands=script_file.read(),
                MulticastPackageVersion=config.MulticastPackageVersion
            )
        else:
            multicast_package = MulticastPackage_1_3.MulticastPackage.create(
                Copyright=config.Copyright,
                TargetCommercialName=config.TargetCommercialName,
                Target12nc=config.Target12nc,
                TargetEntityID=config.TargetEntityID,
                requiredFreeBytesNonVolatileMemory=config.requiredFreeBytesNonVolatileMemory,
                requiredFreeBytesTransientMemory=config.requiredFreeBytesTransientMemory,
                MulticastPackageName=config.MulticastPackageName,
                MulticastPackageDescription=config.MulticastPackageDescription,
                SubComponentMetaData=config.SubComponentMetaData,
                SignatureOverCommands=SignatureParser.SignatureParser.get_signature(args.script_file),
                MulticastCommands=script_file.read(),
                PkSemsCaAut=config.PkSemsCaAut,
                MulticastPackageVersion=config.MulticastPackageVersion
            )

    json_content = multicast_package.to_json()

    with open(args.out, 'w') as out_file:
        out_file.write(json_content)


if __name__ == "__main__":
    main()




