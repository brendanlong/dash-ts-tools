from itertools import count
import logging

from bitstring import BitStream
from common import to_json
import struct


def read_ts(file_name):
    with open(file_name, "rb") as f:
        for byte_offset in count(step=TSPacket.SIZE):
            ts_data = f.read(TSPacket.SIZE)
            if not ts_data:
                break
            yield TSPacket(ts_data, byte_offset)


def read_pes(file_name):
    pmt_pid = None
    pes_readers = {}
    for ts_packet in read_ts(file_name):
        if ts_packet.pid == ProgramAssociationTable.PID:
            pat = ProgramAssociationTable(ts_packet.payload)
            programs = list(pat.programs.values())
            if len(programs) != 1:
                raise Exception("PAT has {} programs, but DASH only "
                                "allows 1 program.".format(len(pat.programs)))
            if pmt_pid is not None and programs[0] != pmt_pid:
                raise Exception("PAT has new PMT PID. This program has "
                                "not been tested to handled this case.")
            pmt_pid = programs[0]

        elif ts_packet.pid == pmt_pid:
            pmt = ProgramMapTable(ts_packet.payload)
            for pid in pmt.streams:
                if pid not in pes_readers:
                    pes_readers[pid] = PESReader()

        elif ts_packet.pid in pes_readers:
            pes_packet = pes_readers[ts_packet.pid].add_ts_packet(ts_packet)
            if pes_packet:
                yield pes_packet


def read_timestamp(name, data):
    timestamp = data.read("uint:3")
    if not data.read("bool"):
        raise Exception("First marker bit in {} section of header is not "
                        "1.".format(name))
    timestamp = (timestamp << 15) + data.read("uint:15")
    if not data.read("bool"):
        raise Exception("Second marker bit in {} section of header is not "
                        "1.".format(name))
    timestamp = (timestamp << 15) + data.read("uint:15")
    if not data.read("bool"):
        raise Exception("Third marker bit in {} section of header is not "
                        "1.".format(name))
    return timestamp


class TSPacket(object):
    SYNC_BYTE = 0x47
    SIZE = 188

    def __init__(self, data, byte_offset):
        self.byte_offset = byte_offset

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
        self.discontinuity_indicator = None
        self.random_access_indicator = None
        self.elementary_stream_priority_indicator = None
        if has_adaptation_field:
            adaptation_field_length = data.read("uint:8")
            if adaptation_field_length:
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
                    data.read(6)  # reserved
                    self.program_clock_reference_extension = data.read("uint:9")

                if opcr_flag:
                    self.original_program_clock_reference_base = data.read(
                        "uint:33")
                    data.read(6)  # reserved
                    self.original_program_clock_reference_extension = data.read(
                        "uint:9")

                if splicing_point_flag:
                    self.splice_countdown = data.read("uint:8")

                if transport_private_data_flag:
                    transport_private_data_length = data.read("uint:8")
                    self.private_data = data.read(
                        transport_private_data_length * 8).bytes

                if adaptation_field_extension_flag:
                    adaptation_field_extension_length = data.read("uint:8")
                    ltw_flag = data.read("bool")
                    piecewise_rate_flag = data.read("bool")
                    seamless_splice_flag = data.read("bool")
                    data.read(5)  # reserved

                    if ltw_flag:
                        self.ltw_valid_flag = data.read("bool")
                        self.ltw_offset = data.read("uint:15")

                    if piecewise_rate_flag:
                        data.read(2)  # reserved
                        self.piecewise_rate = data.read("uint:22")

                    if seamless_splice_flag:
                        self.splice_type = data.read("uint:4")
                        self.dts_next_au = read_timestamp("DTS_next_AU", data)

                data.read(((adaptation_field_length + 5) - data.bytepos) * 8)

        if has_payload:
            self.payload = data.read("bytes")
        else:
            self.payload = None

    def __repr__(self):
        return to_json(self)


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
            raise Exception(
                "table_id for PAT is {} but should be {}".format(
                    self.table_id, self.TABLE_ID))
        self.section_syntax_indicator = data.read("bool")
        self.private_indicator = data.read("bool")
        data.read(2)  # reserved
        section_length = data.read("uint:12")
        self.transport_stream_id = data.read("uint:16")
        data.read(2)  # reserved
        self.version_number = data.read("uint:5")
        self.current_next_indicator = data.read("bool")
        self.section_number = data.read("uint:8")
        self.last_section_number = data.read("uint:8")

        num_programs = (section_length - 9) // 4
        self.programs = {}
        for _ in range(num_programs):
            program_number = data.read("uint:16")
            data.read(3)  # reserved
            pid = data.read("uint:13")
            self.programs[program_number] = pid
        self.crc = data.read("uint:32")

        while data.bytepos < len(data.bytes):
            padding_byte = data.read("uint:8")
            if padding_byte != 0xFF:
                raise Exception("Padding byte at end of PAT was 0x{:X} but "
                                "should be 0xFF".format(padding_byte))

    def __repr__(self):
        return to_json(self)


class Descriptor(object):
    def __init__(self, data):
        self.tag = data.read("uint:8")
        length = data.read("uint:8")
        self.contents = data.read(length * 8).bytes

    @property
    def size(self):
        return 2 + len(self.contents)

    def __repr__(self):
        return to_json(self)

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
        data.read(3)  # reserved
        self.elementary_pid = data.read("uint:13")
        data.read(4)  # reserved
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
            raise Exception(
                "table_id for PMT is {} but should be {}".format(
                    self.table_id, self.TABLE_ID))
        self.section_syntax_indicator = data.read("bool")
        self.private_indicator = data.read("bool")
        data.read(2)  # reserved
        section_length = data.read("uint:12")

        self.program_number = data.read("uint:16")
        data.read(2)  # reserved
        self.version_number = data.read("uint:5")
        self.current_next_indicator = data.read("bool")
        self.section_number = data.read("uint:8")
        self.last_section_number = data.read("uint:8")

        data.read(3)  # reserved
        self.pcr_pid = data.read("uint:13")

        data.read(4)  # reserved
        program_info_length = data.read("uint:12")
        self.descriptors = Descriptor.read_descriptors(
            data, program_info_length)

        self.streams = {}
        while data.bytepos < section_length + 3 - 4:
            stream = Stream(data)
            self.streams[stream.elementary_pid] = stream

        self.crc = data.read("uint:32")

        while data.bytepos < len(data.bytes):
            padding_byte = data.read("uint:8")
            if padding_byte != 0xFF:
                raise Exception("Padding byte at end of PAT was 0x{:02X} but "
                                "should be 0xFF".format(padding_byte))

    def __repr__(self):
        return to_json(self)


class PESReader(object):
    def __init__(self):
        self.ts_packets = []
        self.length = None
        self.data = []

    def add_ts_packet(self, ts_packet):
        if not self.ts_packets and not ts_packet.payload_unit_start_indicator:
            logging.debug("First TS packet for PID 0x{:02X} does not have "
                          "payload_unit_start_indicator = 1. Ignoring this "
                          "packet.".format(ts_packet.pid))
            return None

        self.ts_packets.append(ts_packet)
        if ts_packet.payload:
            self.data.extend(ts_packet.payload)
        if self.length is None and len(self.data) >= 6:
            self.length, = struct.unpack("!xxxxH", bytes(self.data[:6]))
            self.length -= 6

        if len(self.data) < self.length:
            return None

        try:
            pes_packet = PESPacket(bytes(self.data), self.ts_packets)
        except Exception as e:
            logging.warning(e)
            pes_packet = None

        self.ts_packets = []
        self.data = []
        self.length = None
        return pes_packet


class StreamID(object):
    PROGRAM_STREAM_MAP = 0xBC
    PADDING = 0xBE
    PRIVATE_2 = 0xBF
    ECM = 0xF0
    EMM = 0xF1
    PROGRAM_STREAM_DIRECTORY = 0xFF
    DSMCC = 0xF2
    H222_1_TYPE_E = 0xF8

    @staticmethod
    def has_pes_header(sid):
        return sid != StreamID.PROGRAM_STREAM_MAP \
            and sid != StreamID.PADDING \
            and sid != StreamID.PRIVATE_2 \
            and sid != StreamID.ECM \
            and sid != StreamID.EMM \
            and sid != StreamID.PROGRAM_STREAM_DIRECTORY \
            and sid != StreamID.DSMCC \
            and sid != StreamID.H222_1_TYPE_E


class PESPacket(object):
    def __init__(self, data, ts_packets):
        first_ts = ts_packets[0]
        self.pid = first_ts.pid
        self.byte_offset = first_ts.byte_offset
        self.size = len(ts_packets) * TSPacket.SIZE
        self.random_access = first_ts.random_access_indicator

        self.ts_packets = ts_packets
        data = BitStream(data)

        start_code = data.read("uint:24")
        if start_code != 0x000001:
            raise Exception("packet_start_code_prefix is 0x{:06X} but should "
                            "be 0x000001".format(start_code))

        self.stream_id = data.read("uint:8")
        pes_packet_length = data.read("uint:16")

        if StreamID.has_pes_header(self.stream_id):
            bits = data.read("uint:2")
            if bits != 2:
                raise Exception("First 2 bits of a PES header should be 0x2 "
                                "but saw 0x{:02X}'".format(bits))

            self.pes_scrambling_control = data.read("uint:2")
            self.pes_priority = data.read("bool")
            self.data_alignment_indicator = data.read("bool")
            self.copyright = data.read("bool")
            self.original_or_copy = data.read("bool")
            pts_dts_flags = data.read("uint:2")
            escr_flag = data.read("bool")
            es_rate_flag = data.read("bool")
            dsm_trick_mode_flag = data.read("bool")
            additional_copy_info_flag = data.read("bool")
            pes_crc_flag = data.read("bool")
            pes_extension_flag = data.read("bool")
            pes_header_data_length = data.read("uint:8")

            if pts_dts_flags & 2:
                bits = data.read("uint:4")
                if bits != pts_dts_flags:
                    raise Exception(
                        "2 bits before PTS should be 0x{:02X} but saw 0x{"
                        ":02X}".format(pts_dts_flags, bits))
                self.pts = read_timestamp("PTS", data)

            if pts_dts_flags & 1:
                bits = data.read("uint:4")
                if bits != 0x1:
                    raise Exception("2 bits before DTS should be 0x1 but saw "
                                    "0x{:02X}".format(bits))
                self.dts = read_timestamp("DTS", data)

    def __repr__(self):
        d = self.__dict__.copy()
        del d["ts_packets"]
        return to_json(d)
