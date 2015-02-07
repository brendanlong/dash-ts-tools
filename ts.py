from bitstring import BitStream
from collections import defaultdict
from common import to_json
import json
import struct


class TSPacket(object):
    SYNC_BYTE = 0x47
    SIZE = 188

    def __init__(self, data):
        data = BitStream(data)
        sync_byte = data.read("uint:8")
        if sync_byte != TSPacket.SYNC_BYTE:
            raise Exception("First byte of TS packet is not a sync byte.")

        self.transport_error_indicator = data.read("bool")
        self.payload_unit_start_indicator = data.read("bool")
        self.transport_priority = data.read("bool")
        self.pid = data.read("uint:13")
        self.scrambling_control = data.read("uint:2")

        # adaptation_field_control
        has_adaptation_field = data.read("bool")
        has_payload = data.read("bool")

        self.continuity_counter = data.read("uint:4")

        self.program_clock_reference_base = None
        self.program_clock_reference_extension = None
        self.original_program_clock_reference_base = None
        self.original_program_clock_reference_extension = None
        self.splice_countdown = None
        self.private_data = None
        self.ltw_valid_flag = None
        self.ltw_offset = None
        self.piecewise_rate = None
        self.splice_type = None
        self.dts_next_au = None
        if has_adaptation_field:
            adaptation_field_length = data.read("uint:8")
            self.discontinuity_indicator = data.read("bool")
            self.random_access_indicator = data.read("bool")
            self.elementary_stream_priority_indicator = data.read("bool")
            pcr_flag = data.read("bool")
            opcr_flag = data.read("bool")
            splicing_point_flag = data.read("bool")
            transport_private_data_flag = data.read("bool")
            adaptation_field_extension_flag = data.read("bool")

            if pcr_flag:
                self.program_clock_reference_base = data.read("uint:33")
                data.read(6) # reserved
                self.program_clock_reference_extension = data.read("uint:9")

            if opcr_flag:
                self.original_program_clock_reference_base = data.read(
                    "uint:33")
                data.read(6) # reserved
                self.original_program_clock_reference_extension = data.read(
                    "uint:9")

            if splicing_point_flag:
                self.splice_countdown = data.read("uint:8")

            if transport_private_data_flag:
                transport_private_data_length = data.read("uint:8")
                self.private_data = data.read(transport_private_data_length \
                    * 8).bytes

            if adaptation_field_extension_flag:
                adaptation_field_extension_length = data.read("uint:8")
                ltw_flag = data.read("bool")
                piecewise_rate_flag = data.read("bool")
                seamless_splice_flag = data.read("bool")
                data.read(5) # reserved

                if ltw_flag:
                    self.ltw_valid_flag = data.read("bool")
                    self.ltw_offset = data.read("uint:15")

                if piecewise_rate_flag:
                    data.read(2) # reserved
                    self.piecewise_rate = data.read("uint:22")

                if seamless_splice_flag:
                    self.splice_type = data.read("uint:4")
                    self.dts_next_au = data.read("uint:3")
                    if not data.read("bool"):
                        raise Exception("First market bit in seamless splice "
                            "section of header is not 1.")
                    self.ts_next_au = self.ts_next_au << 3 \
                        + data.read("uint:15")
                    if not data.read("bool"):
                        raise Exception("Second market bit in seamless splice "
                            "section of header is not 1.")
                    self.ts_next_au = self.ts_next_au << 15 \
                        + data.read("uint:15")
        else:
            self.discontinuity_indicator = None
            self.random_access_indicator = None
            self.elementary_stream_priority_indicator = None

        if has_payload:
            self.payload = data.read("bytes")
        else:
            self.payload = None

    def __repr__(self):
        return json.dumps(self, default=to_json)


class ProgramAssociationTable(object):
    PID = 0x00
    TABLE_ID = 0x00

    def __init__(self, data):
        data = BitStream(data)
        pointer_field = data.read("uint:8")
        if pointer_field:
            data.read(pointer_field)

        self.table_id = data.read("uint:8")
        if self.table_id != self.TABLE_ID:
            raise Exception("table_id for PAT is {} but should be {}".format(
                self.table_id, self.TABLE_ID))
        self.section_syntax_indicator = data.read("bool")
        self.private_indicator = data.read("bool")
        data.read(2) # reserved
        section_length = data.read("uint:12")
        self.transport_stream_id = data.read("uint:16")
        data.read(2) # reserved
        self.version_number = data.read("uint:5")
        self.current_next_indicator = data.read("bool")
        self.section_number = data.read("uint:8")
        self.last_section_number = data.read("uint:8")

        num_programs = (section_length - 9) // 4
        self.programs = {}
        for i in range(num_programs):
            program_number = data.read("uint:16")
            data.read(3) # reserved
            pid = data.read("uint:13")
            self.programs[program_number] = pid
        self.crc = data.read("uint:32")

        while data.bytepos < len(data.bytes):
            padding_byte = data.read("uint:8")
            if padding_byte != 0xFF:
                raise Exception("Padding byte at end of PAT was 0x{:X} but should "
                    "be 0xFF".format(padding_byte))

    def __repr__(self):
        return json.dumps(self, default=to_json)


class Descriptor(object):
    def __init__(self, data):
        self.tag = data.read("uint:8")
        length = data.read("uint:8")
        self.contents = data.read(length * 8).bytes

    @property
    def size(self):
        return 2 + len(self.contents)

    def __repr__(self):
        return json.dumps(self, default=to_json)

    @staticmethod
    def read_descriptors(data, size):
        total = 0
        descriptors = []
        while total < size:
            descriptor = Descriptor(data)
            descriptors.append(descriptor)
            total += descriptor.size
        if total != size:
            raise Exception("Excepted {} byts of descriptors, but got "
                "{} bytes of descriptors.".format(size, total))
        return descriptors


class Stream(object):
    def __init__(self, data):
        self.stream_type = data.read("uint:8")
        data.read(3) # reserved
        self.elementary_pid = data.read("uint:13")
        data.read(4) # reserved
        es_info_length = data.read("uint:12")
        self.descriptors = Descriptor.read_descriptors(data, es_info_length)


class ProgramMapTable(object):
    TABLE_ID = 0x02

    def __init__(self, data):
        data = BitStream(data)
        pointer_field = data.read("uint:8")
        if pointer_field:
            data.read(pointer_field)

        self.table_id = data.read("uint:8")
        if self.table_id != self.TABLE_ID:
            raise Exception("table_id for PMT is {} but should be {}".format(
                self.table_id, self.TABLE_ID))
        self.section_syntax_indicator = data.read("bool")
        self.private_indicator = data.read("bool")
        data.read(2) # reserved
        section_length = data.read("uint:12")

        self.program_number = data.read("uint:16")
        data.read(2) # reserved
        self.version_number = data.read("uint:5")
        self.current_next_indicator = data.read("bool")
        self.section_number = data.read("uint:8")
        self.last_section_number = data.read("uint:8")

        data.read(3) # reserved
        self.pcr_pid = data.read("uint:13")

        data.read(4) # reserved
        program_info_length = data.read("uint:12")
        self.descriptors = Descriptor.read_descriptors(data,
            program_info_length)

        self.streams = {}
        while data.bytepos < section_length + 3 - 4:
            stream = Stream(data)
            self.streams[stream.elementary_pid] = stream

        self.crc = data.read("uint:32")

        while data.bytepos < len(data.bytes):
            padding_byte = data.read("uint:8")
            if padding_byte != 0xFF:
                raise Exception("Padding byte at end of PAT was 0x{:X} but should "
                    "be 0xFF".format(padding_byte))

    def __repr__(self):
        return json.dumps(self, default=to_json)
