"""Traffic probe of the flow stand.

Every server answers with the source address it saw, so the client learns
which way its packets went: through the uplink (the node's own address) or
through the exit (the exit's egress address). Clients use connected sockets,
so a reply arriving from an unexpected address is dropped and shows up as a
timeout instead of a false pass.

    probe.py serve <addr> <tcp-ports> <udp-ports>
    probe.py tcp <dst> <port> [--bind PORT] [--src ADDR] [--mark MARK] [--payload HEX]
    probe.py udp <dst> <port> [--bind PORT] [--src ADDR] [--mark MARK] [--payload HEX]
    probe.py hold <dst> <port> <flag-file>
    probe.py resolve-tcp <dns-server> <name> <port>

resolve-tcp asks <dns-server> for the A record of <name> over plain UDP, as a
tunnel client does, then connects to the answer.

--payload sends the given bytes instead of "ping": the p2p scenarios send a
BitTorrent signature, or a packet that only resembles one.

Output of the client modes is one line: "src=<address>" or "err=<reason>".
"""

import errno
import os
import socket
import struct
import sys
import threading
import time

TIMEOUT = 2.0


def family(addr):
    return socket.AF_INET6 if ":" in addr else socket.AF_INET


def serve_tcp(addr, port):
    srv = socket.socket(family(addr), socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((addr, port))
    srv.listen(16)
    while True:
        conn, peer = srv.accept()
        threading.Thread(target=echo_tcp, args=(conn, peer), daemon=True).start()


def echo_tcp(conn, peer):
    with conn:
        while conn.recv(64):
            conn.sendall(f"src={peer[0]}\n".encode())


def serve_udp(addr, port):
    srv = socket.socket(family(addr), socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((addr, port))
    while True:
        _, peer = srv.recvfrom(64)
        srv.sendto(f"src={peer[0]}\n".encode(), peer)


def serve(addr, tcp_ports, udp_ports):
    for p in ports(tcp_ports):
        threading.Thread(target=serve_tcp, args=(addr, p), daemon=True).start()
    for p in ports(udp_ports):
        threading.Thread(target=serve_udp, args=(addr, p), daemon=True).start()
    while True:
        time.sleep(3600)


def ports(arg):
    return [int(p) for p in arg.split(",") if p]


SO_MARK = 36


def client(kind, dst, port, bind, mark, src=None, payload=b"ping"):
    sock_type = socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM
    s = socket.socket(family(dst), sock_type)
    s.settimeout(TIMEOUT)
    if mark:
        s.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
    if bind or src:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((src or ("::" if ":" in dst else "0.0.0.0"), bind))
    s.connect((dst, port))
    s.send(payload)
    return s.recv(64).decode().strip()


def hold(dst, port, flag):
    """Opens a TCP connection, asks once, waits for flag, asks again.

    Proves where an already established connection goes after the rules
    change underneath it.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    s.connect((dst, port))
    s.send(b"1")
    before = s.recv(64).decode().strip()
    deadline = time.time() + 20
    while not os.path.exists(flag) and time.time() < deadline:
        time.sleep(0.05)
    s.send(b"2")
    after = s.recv(64).decode().strip()
    return f"{before} {after}"


def resolve(server, name):
    query = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        query += bytes([len(label)]) + label.encode()
    query += b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    s.sendto(query, (server, 53))
    data, _ = s.recvfrom(512)
    answers = struct.unpack(">H", data[6:8])[0]
    pos = len(query)
    for _ in range(answers):
        pos += 2 if data[pos] & 0xC0 == 0xC0 else data.index(b"\x00", pos) + 1 - pos
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        if rtype == 1:
            return socket.inet_ntoa(data[pos:pos + 4])
        pos += rdlen
    raise OSError(errno.ENOENT, "no A record")


def reason(exc):
    if isinstance(exc, socket.timeout):
        return "timeout"
    if isinstance(exc, OSError) and exc.errno:
        return errno.errorcode.get(exc.errno, str(exc.errno))
    return type(exc).__name__


def main(argv):
    mode = argv[1]
    if mode == "serve":
        serve(argv[2], argv[3], argv[4])
        return
    try:
        if mode == "hold":
            print(hold(argv[2], int(argv[3]), argv[4]))
            return
        if mode == "resolve-tcp":
            print(client("tcp", resolve(argv[2], argv[3]), int(argv[4]), 0, 0))
            return
        opts = dict(zip(argv[4::2], argv[5::2]))
        bind = int(opts.get("--bind", "0"))
        mark = int(opts.get("--mark", "0"), 0)
        src = opts.get("--src")
        payload = bytes.fromhex(opts.get("--payload", b"ping".hex()))
        print(client(mode, argv[2], int(argv[3]), bind, mark, src, payload))
    except Exception as exc:  # noqa: BLE001 — the probe reports, the test judges
        print(f"err={reason(exc)}")


if __name__ == "__main__":
    main(sys.argv)
