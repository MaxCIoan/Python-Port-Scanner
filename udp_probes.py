# udp_probes.py

UDP_PROBES = {

    53: (
        "domain",
        b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x06google\x03com\x00\x00\x01\x00\x01"
    ),

    69: (
        "tftp",
        b"\x00\x01test\x00octet\x00"
    ),

    111: (
        "rpcbind",
        b"\x80\x00\x00\x28" + 40 * b"\x00"
    ),

    123: (
        "ntp",
        b"\x1b" + 47 * b"\x00"
    ),

    137: (
        "netbios-ns",
        b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
    ),

    161: (
        "snmp",
        b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04"
        b"\x71\xb4\xb5\x68\x02\x01\x00\x02\x01\x00\x30\x0b"
        b"\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
    ),

    1900: (
        "ssdp",
        b"M-SEARCH * HTTP/1.1\r\nST:ssdp:all\r\nMX:2\r\nMAN:\"ssdp:discover\"\r\n\r\n"
    ),

    500: (
        "isakmp",
        b"\x00" * 20
    ),

    520: (
        "rip",
        b"\x01\x01\x00\x00"
    ),

    2049: (
        "nfs",
        b"\x80\x00\x00\x28" + 40 * b"\x00"
    )

}


def get_probe(port):
    """Return UDP probe packet for a port"""
    if port in UDP_PROBES:
        return UDP_PROBES[port][1]

    return b"\x00"


def get_probe_service(port):
    """Return service name from probe database"""
    if port in UDP_PROBES:
        return UDP_PROBES[port][0]

    return None