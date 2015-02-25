import bitstring
from bitstring import BitStream
from common import to_json
import struct


class Box(object):
    def __init__(self, box_type):
        if isinstance(box_type, str):
            box_type = box_type.encode("ASCII")
        self.type = box_type

    @property
    def size(self):
        return 8

    @property
    def bytes(self):
        return struct.pack("!I4s", self.size, self.type)

    def __repr__(self):
        return to_json(self)


class StypBox(Box):
    def __init__(self, major_brand, minor_version=0, compatible_brands=None):
        super().__init__("styp")

        if isinstance(major_brand, str):
            major_brand = major_brand.encode("ASCII")
        self.major_brand = major_brand
        self.minor_version = minor_version

        self.compatible_brands = set()
        self.compatible_brands.add(major_brand)
        for brand in compatible_brands or []:
            if isinstance(brand, str):
                brand = brand.encode("ASCII")
            self.compatible_brands.add(brand)

    @property
    def size(self):
        return super().size + 8 + len(self.compatible_brands) * 4

    @property
    def bytes(self):
        binary = super().bytes + struct.pack("!4sI", self.major_brand,
            self.minor_version)
        for brand in self.compatible_brands:
            binary += struct.pack("!4s", brand)
        return binary


class FullBox(Box):
    def __init__(self, box_type, version, flags):
        super().__init__(box_type)

        self.version = version
        self.flags = flags

    @property
    def size(self):
        return Box.size.fget(self) + 4

    @property
    def bytes(self):
        return Box.bytes.fget(self) + struct.pack("!BBH",
            self.version, self.flags >> 16, self.flags & 0xFF)


class SidxReference(object):
    class ReferenceType:
        MEDIA = 0
        INDEX = 1

    def __init__(self, reference_type):
        self.reference_type = reference_type
        self.referenced_size = 0
        self.subsegment_duration = 0
        self.starts_with_sap = 0
        self.sap_type = 0
        self.sap_delta_time = 0

    @property
    def size(self):
        return 12

    @property
    def bytes(self):
        return bitstring.pack("bool, uint:31, uint:32, bool, uint:3, uint:28",
            self.reference_type, self.referenced_size, self.subsegment_duration,
            self.starts_with_sap, self.sap_type, self.sap_delta_time).bytes


class SidxBox(FullBox):
    def __init__(self, version=0):
        super().__init__("sidx", version, 0)

        self.reference_id = 0
        self.timescale = 90000
        self.earliest_presentation_time = 0
        self.first_offset = 0
        self.references = []

    @property
    def size(self):
        total = super().size + 12
        if self.version == 0:
            total += 8
        else:
            total += 16
        for reference in self.references:
            total += reference.size
        return total

    @property
    def bytes(self):
        binary = super().bytes + struct.pack("!II", self.reference_id,
            self.timescale)
        if self.version == 0:
            binary += struct.pack("!II", self.earliest_presentation_time,
                self.first_offset)
        else:
            binary += struct.pack("!QQ", self.earliest_presentation_time,
                self.first_offset)
        binary += struct.pack("!HH", 0, len(self.references))
        for reference in self.references:
            binary += reference.bytes
        return binary
