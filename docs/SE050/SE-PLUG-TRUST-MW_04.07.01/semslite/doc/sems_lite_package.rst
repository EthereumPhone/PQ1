..
    Copyright 2019,2020 NXP


=================================================
 Update Package
=================================================


SEMS Lite agent gets an *update package* from  the *update manager*. The upgrade package contains package meta data header and set of APDUs(MulticastCommands) to be sent to the SE for update. It may optionally also contain host control commands (e.g. Reset the secure element).

Format of the *update package*:

.. image:: /Package.jpeg
      :align: center
      :width: 270px


NXP provides customer package meta data and Multicast commands in JSON file. NXP also provides generator tool to turn the JSON file to binary file and .c/.h files. Customer can decide which one to be used by *update manager* according to their platform. *Update manager* should create *update package* from these files. This chapter has provided examples for the use of generator. It also provides links to the demos which will use the generated files to create *update package*.


Package Meta Data
======================================================================

Package meta data includes information such as version and memory requirement. These information will help SEMS Lite agent to preprocess package before loading APDU commands to SE.

* MulticastPackageFormatVersion: Version information of this json Format for MulticastPackages.

* TargetEntityID: Entity ID, 16bytes long Binary Coded Decimal, of the target device where this MulticastPackage is intended to be executed on. It is an identifier of the key-set of the Multicast Applet Loader.

* Target12nc: Target 12nc is a 12 digit numerical code identifying the target device where this MulticastPackage is intended to be executed on, as known to customers and used on EdgeLock2Go to identify device types.

* PkSemsCaAut: The PkSemsCaAut key found in the SEMS_SP_AUT.txt file as PK.AP.AUT.

* requiredFreeBytesNonVolatileMemory: Minimum required free Non Volatile memory in bytes that have to be available on the target device before execution of this MulticastPackage.

* requiredFreeBytesTransientMemory: Minimum required free transient (RAM) memory in bytes that have to be available on the target device before execution of this MulticastPackage.

* MulticastPackageName: Giving a descriptive name to the complete Multicast Package.

* MulticastPackageVersion: Version information of this MulticastPackage, describing the sum version over all contained content.

* SubComponentMetaData: A list of subcomponents of this MulticastPackage, designating all Executable Load Files (ELFs) Contained. It usually contains one entry, but can have multiple in the case multiple dependent ELFs get modified. This list can be empty, e.g. for a KeyRotation or deletion of content.

* SubComponentMetaData name: A human readable name for this subcomponent.

* SubComponentMetaData aid: The Application Identifier (AID) of the Executable Load File (ELF) which makes up the content of this subcomponent. This is stored as string to have it formatted in upper-case hexadecimal and therefore recognizable form.

* SubComponentMetaData version: Version information of this subcomponent.

* SubComponentMetaData SWContentRegister: NXP Software Content Register, specifies the Outgoing License, mostly: LA_OPT_NXP_Software_License.

* SubComponentMetaData minimumPreviousVersion: Minimum version number of this subcomponent as installed on the secure element before this script is executed. If this field is omitted there is no minimum version requirement, e.g. initial Installation of an applet.

* SignatureOverCommands: The signature over the multicast commands in an machine readable form. So it does not have to be parsed form the script commands. String encoding (upper-case hexadecimal) is chosen here, as many json parsers can not handle such large integer values.

* MulticastCommands: The complete Multicast Applet Loader Script (certificate, signature, encrypted and signed commands) in ls-cgt format, encoded in base64.



MulticastCommands In Protocol Buffer Format
======================================================================

.. note:: Advanced information

    The information below is for advanced users and
    kept here for the sake of completeness of information.
    This section can be skipped.

Technically, the APDUS(MulticastCommands) in *update package* is encoded in Protocol Buffers format
(https://developers.google.com/protocol-buffers/) as defined below


.. literalinclude:: Dispatcher.proto
   :language: protobuf
   :start-after: /* doc:request-response:start */
   :end-before: /* doc:request-response:end */

.. literalinclude:: Dispatcher.proto
   :language: protobuf
   :start-after: /* doc:request-response-payload:start */
   :end-before: /* doc:request-response-payload:end */


.. literalinclude:: Apdu.proto
   :language: protobuf
   :start-after: /* doc:apdu-reqeuest:start */
   :end-before: /* doc:apdu-reqeuest:end */


Generator Tools
======================================================================

NXP provides 2 generator tools in ``semslit/tools/sems-lite-generator`` directory:

- JSON Generator:
  A tool to convert the output of CGT tool to a JSON format output

- SEMS Lite generator:
  A tool to convert JSON output to binary file and .c/.h files which will be used by *update manager*

.. image:: /Package_generator.jpeg
      :align: center
      :width: 270px

JSON Generator
----------------------------------------------------------------------
Usage: MulticastPackageCli.py [-h] --pkg_format [PKG_FORMAT_VERSION] --config_file [CONFIG_FILE] --script_file [SCRIPT_FILE] --out [OUT]

Arguments:

-  --pkg_format [PKG_FORMAT_VERSION]
                        Package format version. It can be either 1.2 or 1.3.

-  --config_file [CONFIG_FILE]
                        Config File for MulticastPackage generation. It should follow the format defined in ``semslit/tools/sems-lite-generator/schema/MulticastPackage.jsonschema``. NXP provides an example in ``semslit/tools/sems-lite-generator/config/ExampleConfig_x_x.json``

-  --script_file [SCRIPT_FILE]
                        Encrypted and Signed script as output by the ls-cgt tool.

-  --out [OUT]
                        Output MulticastPackage json file.


Example:

  python ./MulticastPackageCli.py --pkg_format 1.3 --config_file .\config.json --script_file .\encrypted.txt --out .\Upgrade_IoTApplet.json


.. _sems-lite-generator:

SEMS Lite Generator
----------------------------------------------------------------------

Usage: generate.py [-h] [-i INPUT_JSON] [-o OUTPUT_PATH] [-n NAME] [-p PROTOC_PATH]

Process sems-lite-generator arguments

Arguments:
  -h, --help            show this help message and exit
  -i, --input_json INPUT_JSON
                        input json file
  -o, --output_path OUTPUT_PATH
                        output folder path
  -n, --name NAME       stem name of output files. By default, it would use the same name as input json file.
  -p, --protoc_path PROTOC_PATH
                        protoc file path. Use tools/mw_onverter/protoc.exe by default

Example:

  python ./generate.py -i ./Upgrade_NXP-IoTApplet-7.3.json -o ./

The generated files:

* Upgrade_NXP-IoTApplet-7.3.bin: Binary file. It can be used for platforms that have a file system (Windows, Linux, etc). It is encoded in TLV as following:

.. code-block:: cpp

    0x21  Len                             multicastPackage
      |-  0x22  Len  Major Minor          MulticastPackageFormatVersion
      |-  0x23  Len  Binary               TargetEntityID
      |-  0x2f  Len  Binary               Target12nc
      |-  0x31  Len  Binary               PkSemsCaAut
      |-  0x24  Len  u32/u16              requiredFreeBytesNonVolatileMemory
      |-  0x25  Len  u32/u16              requiredFreeBytesTransientMemory
      |-  0x26  Len  String               MulticastPackageName
      |-  0x27  Len  Major Minor          MulticastPackageVersion
      |-  0x28  Len  SubComponentMetaData
      |-    |-  0x2B  Len  String         SubComponentMetaData1.name
      |-    |-  0x2C  Len  Binary         SubComponentMetaData1.aid
      |-    |-  0x2D  Len  Major Minor    SubComponentMetaData1.version
      |-    |-  0x30  Len  String         SubComponentMetaData1.SWContentRegister
      |-    |-  0x2E  Len  Major Minor    SubComponentMetaData1.minimumPreviousVersion
      |-    |-  0x2B  Len  String         SubComponentMetaData2.name
      |-    |-  0x2C  Len  Binary         SubComponentMetaData2.aid
      |-    |-  0x2D  Len  Major Minor    SubComponentMetaData2.version
      |-    |-  0x30  Len  String         SubComponentMetaData2.SWContentRegister
      |-    |-  0x2E  Len  Major Minor    SubComponentMetaData2.minimumPreviousVersion
      ...
      |-    |-  0x2B  Len  String         SubComponentMetaDataN.name
      |-    |-  0x2C  Len  Binary         SubComponentMetaDataN.aid
      |-    |-  0x2D  Len  Major Minor    SubComponentMetaDataN.version
      |-    |-  0x30  Len  String         SubComponentMetaDataN.SWContentRegister
      |-    |-  0x2E  Len  Major Minor    SubComponentMetaDataN.minimumPreviousVersion
      |-  0x29  Len  Binary               SignatureOverCommands
      |-  0x2A  Len  Binary               MulticastCommands



* Upgrade_NXP-IoTApplet-7.3.c and .h: These 2 files instantiate *update package*. They can be integrated into customer tools and can be used for all platforms.


We provide examples for how to use the generated files: :numref:`demo-list-sems-lite` :ref:`demo-list-sems-lite`

Generator Tool Version Compatibility
----------------------------------------------------------------------

NXP provides both SEMS Lite generate tool and JSON format in semslite\\tools folder. In SEMS Lite 3.0.0 (Refer to semslite\\version_info.txt) the JSON package format version is 1.3. But the generate tool in SEMS Lite 3.0.0 can work with the JSON schema of both 1.2 and 1.3.


.. csv-table::
    :file: tool_version_compatibility.csv
