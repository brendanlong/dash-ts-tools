from base64 import b64encode
from bitstring import BitStream
import json


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
                self.private_data = data.read(transport_private_data_length) \
                    .bytes

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
            self.payload = data.tobytes()
        else:
            self.payload = None

    def __repr__(self):
        d = self.__dict__.copy()
        to_remove = []
        for key, value in list(d.items()):
            if value is None:
                del d[key]
        if "payload" in d:
            d["payload"] = b64encode(d["payload"]).decode("UTF-8")
        return json.dumps(d)
