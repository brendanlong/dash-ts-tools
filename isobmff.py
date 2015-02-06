from base64 import b64encode
import json
import struct


class Box(object):
    def __init__(self, type):
        if isinstance(type, str):
            type = type.encode("ASCII")
        self.type = type

    @property
    def size(self):
        return 8

    @property
    def bytes(self):
        return struct.pack("!I4s", self.size, self.type)

    def __repr__(self):
        d = self.__dict__.copy()
        for key, value in list(d.items()):
            if value is None:
                del d[key]
            elif isinstance(value, bytes):
                try:
                    d[key] = value.decode("ASCII")
                except:
                    d[key] = b64encode(value)
        return json.dumps(d)


class StypBox(Box):
    def __init__(self, major_brand, minor_version=0, compatible_brands = None):
        super().__init__("styp")

        if isinstance(major_brand, str):
            major_brand = major_brand.encode("ASCII")
        self.major_brand = major_brand
        self.minor_version = minor_version
        self.compatible_brands = compatible_brands if compatible_brands else []

    @property
    def size(self):
        return super().size + 8 + len(self.compatible_brands) * 4

    @property
    def bytes(self):
        binary = super().bytes + struct.pack("!4sII", self.major_brand,
            self.minor_version, len(self.compatible_brands))
        for brand in self.compatible_brands:
            binary += struct.pack("!4s", brand)
        return binary
