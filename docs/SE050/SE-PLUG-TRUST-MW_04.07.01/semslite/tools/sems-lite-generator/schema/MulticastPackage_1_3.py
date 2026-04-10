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

import base64
import copy
import json
import os
import pathlib
from typing import List
from typing import Optional

import jsonschema


class SubComponentMetaDataType:
    def __init__(self, name: str, aid: str, SWContentRegister: str, version: str, minimumPreviousVersion: Optional[str] = None):
        self.name = name
        self.aid = aid.upper()
        self.version = version
        self.SWContentRegister = SWContentRegister
        if minimumPreviousVersion is not None:
            self.minimumPreviousVersion = minimumPreviousVersion

    @classmethod
    def from_json(cls, json_content: dict):
        return cls(**json_content)


class MulticastPackage:
    MULTICAST_PACKAGE_FORMAT_VERSION = "1.3"

    def __init__(self,
                 Copyright: str,
                 MulticastPackageFormatVersion: str,
                 TargetCommercialName: str,
                 Target12nc: str,
                 TargetEntityID: str,
                 requiredFreeBytesNonVolatileMemory: int,
                 requiredFreeBytesTransientMemory: int,
                 MulticastPackageName: str,
                 MulticastPackageDescription: str,
                 SubComponentMetaData: List[SubComponentMetaDataType],
                 SignatureOverCommands: str,
                 MulticastCommands: str,
                 MulticastPackageVersion: str,
                 PkSemsCaAut: str):
        self.Copyright = Copyright
        self.MulticastPackageFormatVersion = MulticastPackageFormatVersion
        self.TargetCommercialName = TargetCommercialName
        self.Target12nc = Target12nc
        self.TargetEntityID = TargetEntityID
        self.requiredFreeBytesNonVolatileMemory = requiredFreeBytesNonVolatileMemory
        self.requiredFreeBytesTransientMemory = requiredFreeBytesTransientMemory
        self.MulticastPackageName = MulticastPackageName
        self.MulticastPackageDescription = MulticastPackageDescription
        self.SubComponentMetaData = SubComponentMetaData
        self.SignatureOverCommands = SignatureOverCommands
        self.MulticastCommands = MulticastCommands
        self.MulticastPackageVersion = MulticastPackageVersion
        self.PkSemsCaAut = PkSemsCaAut

    @staticmethod
    def create(Copyright: str,
               TargetCommercialName: str,
               Target12nc: str,
               TargetEntityID: str,
               requiredFreeBytesNonVolatileMemory: int,
               requiredFreeBytesTransientMemory: int,
               MulticastPackageName: str,
               MulticastPackageDescription: str,
               SubComponentMetaData: List[SubComponentMetaDataType],
               SignatureOverCommands: str,
               MulticastCommands: str,
               PkSemsCaAut: str,
               MulticastPackageVersion: Optional[str] = None):
        multicast_commands_base64 = str(base64.b64encode(MulticastCommands.encode("utf-8")), "utf-8")
        multicast_package = MulticastPackage(
            Copyright,
            MulticastPackage.MULTICAST_PACKAGE_FORMAT_VERSION,
            TargetCommercialName,
            Target12nc,
            TargetEntityID,
            requiredFreeBytesNonVolatileMemory,
            requiredFreeBytesTransientMemory,
            MulticastPackageName,
            MulticastPackageDescription,
            SubComponentMetaData,
            SignatureOverCommands,
            multicast_commands_base64,
            MulticastPackageVersion,
            PkSemsCaAut)
        # In case exactly one SubComponent is contained the
        # MulticastPackageVersion is equal to the version of this SubComponent.
        if len(SubComponentMetaData) == 1:
            multicast_package.MulticastPackageVersion = SubComponentMetaData[0].version
        return multicast_package

    @staticmethod
    def get_json_schema():
        schema_file = pathlib.Path(os.path.dirname(os.path.realpath(__file__))).absolute() \
                      / 'MulticastPackage_1_3.jsonschema'
        with open(str(schema_file), 'r') as file:
            schema_data = file.read()
        schema = json.loads(schema_data)
        return schema

    def to_json(self):
        json_content = json.dumps(self, default=lambda o: o.__dict__, sort_keys=False, indent=4)
        jsonschema.validate(instance=json.loads(json_content), schema=MulticastPackage.get_json_schema())
        return json_content

    @staticmethod
    def from_json(json_content):
        data = json.loads(json_content)
        jsonschema.validate(instance=json.loads(json_content), schema=MulticastPackage.get_json_schema())
        if data["MulticastPackageFormatVersion"] == MulticastPackage.MULTICAST_PACKAGE_FORMAT_VERSION:
            obj = MulticastPackage(**data)
            obj.SubComponentMetaData = list(map(SubComponentMetaDataType.from_json, data["SubComponentMetaData"]))
            return obj

        raise ValueError("Incorrect MulticastPackageFormatVersion, expected: "
                         + MulticastPackage.MULTICAST_PACKAGE_FORMAT_VERSION + " received: "
                         + data["MulticastPackageFormatVersion"])

    def get_name_and_version(self):
        return self.MulticastPackageName + "-" + self.MulticastPackageVersion

    def get_description(self):
        return self.MulticastPackageDescription

    def get_info(self):
        tmp_copy = copy.deepcopy(self)
        tmp_copy.MulticastCommands = "(not shown in comment)"
        return tmp_copy.to_json()

    def get_multicast_commands(self):
        return base64.b64decode(self.MulticastCommands).decode("utf-8")
