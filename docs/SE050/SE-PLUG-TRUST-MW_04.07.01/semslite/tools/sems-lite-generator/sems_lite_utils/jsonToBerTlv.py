# Copyright 2020 NXP
#
# NXP Confidential. This software is owned or controlled by NXP and may only
# be used strictly in accordance with the applicable license terms.  By
# expressly accepting such terms or by downloading, installing, activating
# and/or otherwise using the software, you are agreeing that you have read,
# and that you agree to comply with and are bound by, such license terms.  If
# you do not agree to be bound by the applicable license terms, then you may
# not retain, install, activate or otherwise use the software.
#
import sys
import struct
import array

class JsonToBerTlv(object):
    def __init__(self,  binFile, hex_bin_file, json_obj, sems_lite_agent_major_version):
        self.binFile = open(binFile, "rb")
        self.hex_bin_file = open(hex_bin_file + '.bin', "wb")
        self.json_obj = json_obj
        self.sems_lite_agent_major_version = sems_lite_agent_major_version
        self.subcomponent_count = 0
        self.buffer = bytearray()
        self.temp_buffer = bytearray()
        self.subcomp_buffer = bytearray()
        self.signature_buffer = bytearray()
        self.command_buffer = bytearray()
        self.target_endian = 'little'  #'big'
        self.temp_length = 0
        self.subcomp_length = 0
        self.command_length = 0
        self.signature_length = 0
        self.buffer_length = 0
        self.total_buffer_length = 0
        pass


    if sys.version > '3':
        def _byte(self, b):
            return bytes((b, ))
    else:
        def _byte(self, b):
            return chr(b)

    def encode_varint(self, number):
        """Pack `number` into varint bytes"""
        buf = b''
        while True:
            towrite = number & 0x7f
            number >>= 7
            if number:
                buf += self._byte(towrite | 0x80)
            else:
                buf += self._byte(towrite)
                break
        return buf


    def gen_TLV_string(self, tag, obj):
        self.temp_length = 0
        self.write_hex_to_buffer(tag, 1)
        length = len(obj) + 1
        if length <= 0X7F:
            self.write_hex_to_buffer(length, 1)
        elif length <= 0xFF:
            self.write_hex_to_buffer(0x81, 1)
            self.write_hex_to_buffer(length, 1)
        elif length <= 0xFFFF:
            self.write_hex_to_buffer(0x82, 1)
            self.write_hex_to_buffer(length, 2)
        elif length <= 0xFFFFFFFF:
            self.write_hex_to_buffer(0x84, 1)
            self.write_hex_to_buffer(length,4)
        else:
            SystemExit('Length validation error, greater than 0xFFFFFFFF')
        self.write_string_to_buffer_as_string(obj)

    def gen_TLV_hex(self, tag, obj):
        self.temp_length = 0
        self.write_hex_to_buffer(tag, 1)
        length = int((len(obj)+1)/2)
        if length <= 0X7F:
            self.write_hex_to_buffer(length, 1)
        elif length <= 0xFF:
            self.write_hex_to_buffer(0x81, 1)
            self.write_hex_to_buffer(length, 1)
        elif length <= 0xFFFF:
            self.write_hex_to_buffer(0x82, 1)
            self.write_hex_to_buffer(length, 2)
        elif length <= 0xFFFFFFFF:
            self.write_hex_to_buffer(0x84, 1)
            self.write_hex_to_buffer(length,4)
        else:
            SystemExit('Length validation error, greater than 0xFFFFFFFF')
        self.write_string_to_buffer_as_hex(obj)

    def gen_TLV_version(self, tag, major, minor):
        self.temp_length = 0
        self.write_hex_to_buffer(tag, 1)
        length = 2
        self.write_hex_to_buffer(length, 1)
        self.write_hex_to_buffer(major, 1)
        self.write_hex_to_buffer(minor, 1)

    def gen_TLV_bytes(self, tag, length, obj):
        self.temp_length = 0
        self.write_hex_to_buffer(tag, 1)
        if length <= 0X7F:
            self.write_hex_to_buffer(length, 1)
        elif length <= 0xFF:
            self.write_hex_to_buffer(0x81, 1)
            self.write_hex_to_buffer(length, 1)
        elif length <= 0xFFFF:
            self.write_hex_to_buffer(0x82, 1)
            self.write_hex_to_buffer(length, 2)
        elif length <= 0xFFFFFFFF:
            self.write_hex_to_buffer(0x84, 1)
            self.write_hex_to_buffer(length,4)
        else:
            SystemExit('Length validation error, greater than 0xFFFFFFFF')
        self.write_bytes_to_buffer(obj, length)

    def turn_binary_blob_to_tlv(self):
        self.temp_buffer = bytearray()
        blob_data = self.binFile.read()
        length = len(blob_data)
        varint_len = self.encode_varint(length)

        self.command_buffer = bytearray()
        self.command_buffer.extend(varint_len)
        self.command_buffer.extend(blob_data)

        total_len = length + len(varint_len)
        self.gen_TLV_bytes(0X2A, total_len, self.command_buffer) # TLV->temp_buffer
        self.command_length = self.temp_length
        self.command_buffer = bytearray()
        self.command_buffer.extend(self.temp_buffer)    # temp_buffer->command_buffer
        self.temp_buffer = bytearray()

        self.binFile.close()

    def turn_subcomponents_to_tlv(self):
        subcomponentlist = self.json_obj["SubComponentMetaData"]
        self.subcomp_buffer = bytearray()
        self.temp_buffer = bytearray()
        self.subcomp_length = 0

        if len(subcomponentlist) == 0:
            self.subcomponent_count = 0

        else:
            self.temp_buffer = bytearray()
            for subcomponent in subcomponentlist:
                self.gen_TLV_string(0X2B, subcomponent["name"])
                self.subcomp_length += self.temp_length
                self.gen_TLV_hex(0X2C, subcomponent["aid"])
                self.subcomp_length += self.temp_length
                data = subcomponent["version"].split(".")
                data = [int(i) for i in data]
                self.gen_TLV_version(0X2D, data[0], data[1])
                self.subcomp_length += self.temp_length
                if "SWContentRegister" in subcomponent.keys():
                    self.gen_TLV_string(0X30, subcomponent["SWContentRegister"])
                    self.subcomp_length += self.temp_length
                if "minimumPreviousVersion" in subcomponent.keys():
                    data = subcomponent["minimumPreviousVersion"].split(".")
                    data = [int(i) for i in data]
                    self.gen_TLV_version(0X2E, data[0], data[1])
                    self.subcomp_length += self.temp_length
                else:
                    self.gen_TLV_version(0X2E, 0xFF, 0xFF)  # Invalid version number
                    self.subcomp_length += self.temp_length
                self.subcomponent_count += 1
        self.subcomp_buffer.extend(self.temp_buffer)    # subcomp_buffer<-temp_buffer
        self.temp_buffer = bytearray()
        self.gen_TLV_bytes(0X28, self.subcomp_length, self.subcomp_buffer) # T+L+V -> temp_buffer
        self.subcomp_length = self.temp_length
        self.subcomp_buffer = bytearray()
        self.subcomp_buffer.extend(self.temp_buffer)    # subcomp_buffer<-temp_buffer
        self.temp_buffer = bytearray()

    # Field before subcomponent
    def turn_fields_to_tlv(self):
        self.temp_buffer = bytearray()
        if (self.target_endian == 'big'):
            self.gen_TLV_bytes(0X22, 4, struct.pack(">I", self.sems_lite_agent_major_version))
        else:
            self.gen_TLV_bytes(0X22, 4, struct.pack("<I", self.sems_lite_agent_major_version))
        self.buffer_length += self.temp_length
        self.gen_TLV_hex(0X23, self.json_obj["TargetEntityID"])
        self.buffer_length += self.temp_length
        self.gen_TLV_hex(0X2f, self.json_obj["Target12nc"])
        self.buffer_length += self.temp_length
        if "PkSemsCaAut" in self.json_obj:
            self.gen_TLV_hex(0X31, self.json_obj["PkSemsCaAut"])
            self.buffer_length += self.temp_length
        if (self.target_endian == 'big'):
            self.gen_TLV_bytes(0X24, 4, struct.pack(">I", self.json_obj["requiredFreeBytesNonVolatileMemory"]))
            self.buffer_length += self.temp_length
            self.gen_TLV_bytes(0X25, 4, struct.pack(">I", self.json_obj["requiredFreeBytesTransientMemory"]))
            self.buffer_length += self.temp_length
        else:
            self.gen_TLV_bytes(0X24, 4, struct.pack("<I", self.json_obj["requiredFreeBytesNonVolatileMemory"]))
            self.buffer_length += self.temp_length
            self.gen_TLV_bytes(0X25, 4, struct.pack("<I", self.json_obj["requiredFreeBytesTransientMemory"]))
            self.buffer_length += self.temp_length
        self.gen_TLV_string(0X26, self.json_obj["MulticastPackageName"])
        self.buffer_length += self.temp_length
        data = self.json_obj["MulticastPackageVersion"].split(".")
        data = [int(i) for i in data]
        self.gen_TLV_version(0X27, data[0], data[1])    # TLV -> temp_buffer
        self.buffer_length += self.temp_length
        self.buffer.extend(self.temp_buffer)    # temp_buffer -> buffer
        self.temp_buffer = bytearray()

    def turn_signature_to_tlv(self):
        self.temp_buffer = bytearray()
        self.gen_TLV_hex(0X29, self.json_obj["SignatureOverCommands"]) # TLV -> temp_buffer
        self.signature_buffer.extend(self.temp_buffer)  # temp_buffer -> signature_buffer
        self.temp_buffer = bytearray()
        self.signature_length = self.temp_length

    def write_string_to_buffer_as_string(self, value):
        tempvar = value+'\0'
        self.temp_buffer.extend(tempvar.encode("ascii"))
        self.temp_length += len(value) + 1

    def write_string_to_buffer_as_hex(self, value):
        hex_len = int((len(value)+1)/2)
        j=int(value, 16)
        temp_bytes = j.to_bytes(hex_len, byteorder='big', signed=False) # Always use hex as it's in fact a string.
        self.temp_buffer.extend(temp_bytes)
        self.temp_length += hex_len

    def write_hex_to_buffer(self, value, byte_num):
        temp_bytes = value.to_bytes(byte_num, byteorder=self.target_endian, signed=False)
        self.temp_buffer.extend(temp_bytes)
        self.temp_length += byte_num

    def write_bytes_to_buffer(self, obj, byte_num):
        self.temp_buffer.extend(obj)
        self.temp_length += byte_num

    def run(self):
        self.turn_subcomponents_to_tlv()
        self.turn_binary_blob_to_tlv()
        self.turn_signature_to_tlv()
        self.turn_fields_to_tlv()
        self.buffer.extend(self.subcomp_buffer)
        self.buffer.extend(self.signature_buffer)
        self.buffer.extend(self.command_buffer)
        self.buffer_length += self.subcomp_length + self.signature_length + self.command_length
        self.temp_buffer = bytearray()
        self.gen_TLV_bytes(0X21, self.buffer_length, self.buffer) # TLV -> temp_buffer
        self.buffer = bytearray()
        self.buffer.extend(self.temp_buffer)    # temp_buffer -> buffer

        self.hex_bin_file.write(self.buffer)
        self.hex_bin_file.flush()

        pass


def main():
    json2ber = JsonToBer("C:\\_ddm\\IOT\\testout\\test.tmpbin", "C:\\_ddm\\IOT\\testout\\testber.bin")
    json2ber.run()


if __name__ == "__main__":
    main()