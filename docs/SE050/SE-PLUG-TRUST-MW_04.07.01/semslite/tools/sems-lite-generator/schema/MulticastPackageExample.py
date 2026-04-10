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

import unittest
import os
import pathlib
import datetime
import MulticastPackage


# Copyright and License
def multicast_package_copyright():
    return "Copyright " + str(datetime.datetime.now().year) + "  NXP"

# Purpose of this unit test is to create example json content
# based on the common use cases: upgrade, deletion, loading (with multiple sub components)
# The unit test only covers positive json schema validation and equality after serialization/deserialization
class MulticastPackageExampleTestCase(unittest.TestCase):
    def setUp(self):
        if not os.path.exists(MulticastPackageExampleTestCase.EXAMPLE_FOLDER):
            os.makedirs(MulticastPackageExampleTestCase.EXAMPLE_FOLDER)

    def test_example_update_multicast_package(self):
        sub_comp = MulticastPackage.SubComponentMetaDataType(
            name="NXP-IoTApplet",
            aid="A00000039654530000000103000200",
            version="4.12",
            minimumPreviousVersion="4.11")
        example_json = MulticastPackage.MulticastPackage.create(
                                Copyright=multicast_package_copyright(),
                                TargetCommercialName="SE051C2HQx/Z0xxx",
                                Target12nc="123456789012",
                                TargetEntityID="88888888888888888888888888888888",
                                requiredFreeBytesNonVolatileMemory=2500,
                                requiredFreeBytesTransientMemory=123,
                                MulticastPackageName="Update_NXP-IoTApplet",
                                MulticastPackageDescription="Package to upgrade the NXP IoT Applet. This is a "
                                                            "non-functional example to illustrate the "
                                                            "MulticastPackage.json format.",
                                SubComponentMetaData=[sub_comp],
                                SignatureOverCommands=MulticastPackageExampleTestCase.EXAMPLE_SIGNATURE_OVER_COMMANDS,
                                MulticastCommands=MulticastPackageExampleTestCase.EXAMPLE_MULTICAST_COMMANDS,
                                MulticastPackageVersion=None)
        json_content = example_json.to_json()
        filename = str(MulticastPackageExampleTestCase.EXAMPLE_FOLDER /
                       (example_json.get_name_and_version() + ".json"))

        with open(filename, 'w') as out_file:
            out_file.write(json_content)
        with open(filename, 'r') as in_file:
            read_back_content = in_file.read()
        self.assertEqual(json_content, read_back_content)

    def test_example_update2_multicast_package(self):
        sub_comp = MulticastPackage.SubComponentMetaDataType(
            name="NXP-IoTApplet",
            aid="A00000039654530000000103000200",
            version="4.13",
            minimumPreviousVersion="4.12")
        example_json = MulticastPackage.MulticastPackage.create(
                                Copyright=multicast_package_copyright(),
                                TargetCommercialName="SE051C2HQx/Z0xxx",
                                Target12nc="123456789012",
                                TargetEntityID="88888888888888888888888888888888",
                                requiredFreeBytesNonVolatileMemory=2550,
                                requiredFreeBytesTransientMemory=124,
                                MulticastPackageName="Update_NXP-IoTApplet",
                                MulticastPackageDescription="Package to upgrade the NXP IoT Applet. This is a "
                                                            "non-functional example to illustrate the "
                                                            "MulticastPackage.json format.",
                                SubComponentMetaData=[sub_comp],
                                SignatureOverCommands=MulticastPackageExampleTestCase.EXAMPLE_SIGNATURE_OVER_COMMANDS,
                                MulticastCommands=MulticastPackageExampleTestCase.EXAMPLE_MULTICAST_COMMANDS,
                                MulticastPackageVersion=None)
        json_content = example_json.to_json()
        filename = str(MulticastPackageExampleTestCase.EXAMPLE_FOLDER /
                       (example_json.get_name_and_version() + ".json"))

        with open(filename, 'w') as out_file:
            out_file.write(json_content)
        with open(filename, 'r') as in_file:
            read_back_content = in_file.read()
        self.assertEqual(json_content, read_back_content)

    def test_example_install_multicast_package(self):
        sub_comp1 = MulticastPackage.SubComponentMetaDataType(
            name="NXP-CiphersuiteApplet",
            aid="A00000039654530000000EEEEEEEEE",
            version="3.45")
        sub_comp2 = MulticastPackage.SubComponentMetaDataType(
            name="NXP-IoTLibraryPackage",
            aid="A0000003965FFFFFFFFFFFFFFFFFFF",
            version="2.1")
        example_json = MulticastPackage.MulticastPackage.create(
                                Copyright=multicast_package_copyright(),
                                TargetCommercialName="SE051P2HQx/Z0xxx",
                                Target12nc="123456789012",
                                TargetEntityID="00000000000000000063709317141245",
                                requiredFreeBytesNonVolatileMemory=7856,
                                requiredFreeBytesTransientMemory=785,
                                MulticastPackageName="Install_NXP-Ciphersuite-Components",
                                MulticastPackageDescription="Package to install the fictional NXP Ciphersuite Applet "
                                                            "and related Library. This is a non-functional example to "
                                                            "illustrate the MulticastPackage.json format.",
                                SubComponentMetaData=[sub_comp1, sub_comp2],
                                SignatureOverCommands=MulticastPackageExampleTestCase.EXAMPLE_SIGNATURE_OVER_COMMANDS,
                                MulticastCommands=MulticastPackageExampleTestCase.EXAMPLE_MULTICAST_COMMANDS,
                                MulticastPackageVersion="1.0")
        json_content = example_json.to_json()
        filename = str(MulticastPackageExampleTestCase.EXAMPLE_FOLDER /
                       (example_json.get_name_and_version() + ".json"))

        with open(filename, 'w') as out_file:
            out_file.write(json_content)
        with open(filename, 'r') as in_file:
            read_back_content = in_file.read()
        self.assertEqual(json_content, read_back_content)

    def test_example_deletion_multicast_package(self):
        example_json = MulticastPackage.MulticastPackage.create(
                                Copyright=multicast_package_copyright(),
                                TargetCommercialName="SE051C2HQx/Z0xxx",
                                Target12nc="123456789012",
                                TargetEntityID="88888888888888888888888888888888",
                                requiredFreeBytesNonVolatileMemory=0,
                                requiredFreeBytesTransientMemory=0,
                                MulticastPackageName="DeletePackage_NXP-PersoApplet",
                                MulticastPackageDescription="Package to delete the NXP PersoApplet. "
                                                            "This is a non-functional example to "
                                                            "illustrate the MulticastPackage.json format.",
                                SubComponentMetaData=[],  # Empty sub component list because we are only deleting
                                SignatureOverCommands=MulticastPackageExampleTestCase.EXAMPLE_SIGNATURE_OVER_COMMANDS,
                                MulticastCommands=MulticastPackageExampleTestCase.EXAMPLE_MULTICAST_COMMANDS,
                                MulticastPackageVersion="1.0")
        json_content = example_json.to_json()
        filename = str(MulticastPackageExampleTestCase.EXAMPLE_FOLDER /
                       (example_json.get_name_and_version() + ".json"))

        with open(filename, 'w') as out_file:
            out_file.write(json_content)
        with open(filename, 'r') as in_file:
            read_back_content = in_file.read()
        self.assertEqual(json_content, read_back_content)

    EXAMPLE_FOLDER = pathlib.Path(
            os.path.dirname(os.path.realpath(__file__))).absolute() / ".." / 'multicast_package_examples'

    # We simply use the same example content, just to illustrate the MulticastPackage.json format
    EXAMPLE_SIGNATURE_OVER_COMMANDS = "30440220863807276F2AA3EEFE98E58A1D146FCCB5B919EAD9F66C6D701F36D9ECCC9B1E0220A" \
                                      "56A0245A1B927D8EAEAFF4F8DF7BB004F324B989F0EBB6072CA1321A13768D8"
    EXAMPLE_MULTICAST_COMMANDS = "N2YyMTgxZWU5MzEwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDE0MjEwODg4ODg4ODg4ODg4OD" \
                                 "g4ODg4ODg4ODg4ODg4ODg4ODg1ZjIwMTBjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjYzk1MDE4" \
                                 "MjQ1MDhjY2NjY2NjY2NjY2NjYzAxNTMxZjQ4MDgwMDAxMDAwMDAwMDIwMDAxNGMwMTAzNGQxMDA3YTAwMD" \
                                 "AwMDM5NjU0NTMwMDAwMDAwMTAzMDAwMjAwNWYzNzQwNTc0MzNkMTU2NWZkNzFjYmY2ZmU5ZjQxODg3NzNi" \
                                 "NTI0M2ZjNDg5M2QwZTI3NGE3NjZlN2QwN2M2MWZhNjNhNTc4MmQ4OTUzZjRhYzFjMDQyOTIzZGE0ZGZlMD" \
                                 "QzM2QzNGEwM2U3NTc0YTVhMDUyZDVlODA4OTAxZjUzMTVjOWU3ZjQ5NDM4NjQxMDQ0ZGYxMDVjOGExYTY4" \
                                 "MzdmMDgwMjViZmVjYTBkNDZjOGY3M2NmOGE4MThmZWNkNzljMGJmNTMzZTA2YjFiMmY2MjdhZTEzOTRmOW" \
                                 "Q3OWU0Zjg3OGQxNDNiNGRkMmI4MTk1OTZmNjIyYjM5YjY4OTMxMDM4NWY0OGFmYjA0ZDEyNwo2MDgxYmE0" \
                                 "MTgxYjcwNDZkYmRiNTRjNjJjNjAwYWFiZWEwM2UyYjM2ZDViMDJjNjQ3NDg5NjNiODUzOTYyYmYyODYzMj" \
                                 "E3YWY3NTE2ZWZhNTg5ZDRmMzBkNDgwZWUzZmZkOTY5NTAyNDUzZTVlMjk3ZmY2NmMyYzJkMzJjZGZhNjNi" \
                                 "MTk5ZGJkNzkwYzRhZmUyY2RhMTJmMWM0ZjYzOWYwNzFjMDA5NzhiZGRkNjJiYTMyOWU1NmZkNWEwMmI2NW" \
                                 "JiYzM1NmE1ZGM5ZDQ1NDk5OTdmMDNiMDg3ODQ5NmQ0MjZjZGEyOGU4ZjYyZWE5MzA0NDAyMjA4NjM4MDcy" \
                                 "NzZmMmFhM2VlZmU5OGU1OGExZDE0NmZjY2I1YjkxOWVhZDlmNjZjNmQ3MDFmMzZkOWVjY2M5YjFlMDIyMG" \
                                 "E1NmEwMjQ1YTFiOTI3ZDhlYWVhZmY0ZjhkZjdiYjAwNGYzMjRiOTg5ZjBlYmI2MDcyY2ExMzIxYTEzNzY4" \
                                 "ZDgKNDA0NTgwYTAwMDAwNDBiYWMzZmI2ZjU0OWU1ZmI3MGY4MWJiYzFjYWFiNWQ0ZjI5YmU1NjAyZTBlNz" \
                                 "Y2ZGU2NWRhZmQ0MjNkODU1ZDNkYTczNGY5NGZjMjkxZTU2MmU4MjRhOGY5OWRiYjJkYWY2YmVhMTJmZjQ1" \
                                 "MWE3NzZkNWJmODc1YTZmY2VkYThmZgo0MDQ1ODBhMDAwMDA0MDUxYWEwMjM5ODJhZjdhNjhiYjZkYzRhZD" \
                                 "M0NTI1M2MzM2M5NjYxODE3ZGRiYjhlOGRkNTNiYmQ5YmVjYTUwOWQxNDliYTg4NDdiMjc3OTA1N2QxYjFm" \
                                 "MjQ5Mzk4NjYxOThjOTIxMWZjMDdmYmE2ZWE1ZmY5ZDk1MDRmZTY4N2QwCjQwNDU4MGEwMDAwMDQwMTIyYz" \
                                 "ZlYjIzMjgxOGFlNjk1NWZjYjc5NDMzODU2NjBlZGExOTAxMDEwNGQzNWRlMmMyYmFjYzBkYjQ2ZDUzODIx" \
                                 "NzA5OTRiNjdkYTVmMmNlOGI5Yjc0OWQ0NjVmYWRhNzEyMGNjOTQyZDk1MTVjZTViMjI1ZjYwYjVjMWJmNG" \
                                 "QKNDA1NTgwYTAwMDAwNTA1MjM2ZDcxZmI4MmJjZmJkYjNmN2RhYzRjNzkzMzcxZGJlYzA5NTc1ZjJjYzE2" \
                                 "OWU2Y2E2ZmYzZWI1Yzk5YTg5ZDI5MDE5NGQ1NjAwZDE2Y2Y4YzM3NGM3MTE2MTFhNzk4YTJkNGRjNGQ4Nz" \
                                 "gxM2M5MDgyMzU5OTU5MTU1Y2Y5YzliNWU5Yjg0ZDU0ZGI1OTZiZDY5NDY4N2U3YWYzNDM5CjQwNDU4MGEw" \
                                 "ODAwMDQwYTVjNzliZGQ2Y2U4MDFhZTc5ODNhNGViOTFiNTA3MzIzZGE4NjRlMzc4NWQxMDY1MjJhNDBhND" \
                                 "Q4NGI3Y2JkZGRmM2Y2MTk4MDRhOTJmZGI0MDU3MTkyZGM0M2RkNzQ4ZWE3NzhhZGM1MmJjNDk4Y2U4MDUy" \
                                 "NGMwMTRiODExMTkK"


if __name__ == '__main__':
    unittest.main()
