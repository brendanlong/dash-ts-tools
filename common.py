from base64 import b64encode

def to_json(o):
    if isinstance(o, bytes):
        try:
            return o.decode("ASCII")
        except:
            return b64encode(o)
    if isinstance(o, set):
        return list(o)
    return o.__dict__
