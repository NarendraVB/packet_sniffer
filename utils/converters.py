def mac_address(raw: bytes) -> str:
    return ":".join(
        f"{byte:02X}"
        for byte in raw
    )

def ipv4_address(raw: bytes) -> str:
    return ".".join(
        str(byte)
        for byte in raw
    )