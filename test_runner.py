#!/usr/bin/env python3
"""
CodeCrafters "Build your own DNS server" - Local Test Runner
Accurately reproduces the test harness from codecrafters-io/dns-server-tester.
Zero external dependencies required (uses only Python standard library).
"""

import sys
import os
import socket
import struct
import time
import subprocess
import threading
import argparse
import random

CHALLENGE_NAME = "Build your own DNS server"
DEFAULT_DOMAIN = "codecrafters.io."
DEFAULT_PKT_ID = 1234
SERVER_ADDR = ("127.0.0.1", 2053)
RESOLVER_ADDR = ("127.0.0.1", 5354)

# Reference DNS records table identical to codecrafters-io/dns-server-tester (dns_records.go)
DNS_RECORDS = {
    "example.com.": {
        1: "127.0.0.1",
        28: "2001:db8::1",
        5: "example-cname.com.",
        15: "10 mail.example.com.",
        2: "ns1.example.com.",
    },
    "google.com.": {
        1: "172.217.3.110",
        28: "2607:f8b0:4006:801::200e",
        15: "5 alt1.aspmx.l.google.com.",
        2: "ns4.google.com.",
    },
    "facebook.com.": {
        1: "31.13.65.36",
        28: "2a03:2880:f12f:83:face:b00c::25de",
        5: "star-mini.c10r.facebook.com.",
    },
    "github.com.": {
        1: "140.82.113.3",
        28: "2606:50c0:8000::64",
    },
    "stackoverflow.com.": {
        1: "151.101.129.69",
        28: "2a73:2580:::face:b00c::25de",
        5: "stackoverflow.design.",
        15: "10 aspmx.l.google.com.",
    },
    "reddit.com.": {
        1: "151.101.65.140",
        28: "2607:f8b0:4006:::200e",
        15: "10 mail.reddit.com.",
    },
    "youtube.com.": {
        1: "172.217.3.110",
        28: "2607:f8b0:4006:801::200e",
    },
    "example-cname.com.": {
        1: "192.168.0.1",
    },
    "mail.example.com.": {
        1: "192.168.0.2",
    },
    "mail.google.com.": {
        1: "173.194.221.27",
    },
    "alt1.aspmx.l.google.com.": {
        1: "173.194.221.27",
    },
    "star-mini.c10r.facebook.com.": {
        1: "31.13.65.36",
    },
    "stackoverflow.design.": {
        1: "151.101.1.69",
    },
    "aspmx.l.google.com.": {
        1: "108.177.119.26",
    },
    "mail.reddit.com.": {
        1: "151.101.65.140",
    },
    "codecrafters.io.": {
        1: "76.76.21.21",
        15: "10 mail.codecrafters.io.",
    },
    "abc.codecrafters.io.": {
        1: "76.76.21.21",
        15: "10 mail.codecrafters.io.",
    },
    "def.codecrafters.io.": {
        1: "76.76.21.21",
        15: "10 mail.codecrafters.io.",
    },
    "abc.longassdomainname.com.": {
        1: "127.0.0.1",
    },
    "def.longassdomainname.com.": {
        1: "127.0.0.2",
    },
}

# ----------------- DNS Protocol Helper Functions -----------------

def encode_name(domain: str) -> bytes:
    """Encode a domain name as RFC 1035 labels ending with 0x00."""
    clean = domain.strip(".")
    if not clean:
        return b"\x00"
    parts = clean.split(".")
    encoded = b"".join(bytes([len(p)]) + p.encode("ascii") for p in parts)
    return encoded + b"\x00"


def decode_name(buf: bytes, offset: int):
    """Decode an RFC 1035 domain name from wire format, supporting compression pointers."""
    labels = []
    jumped = False
    original_offset = offset
    visited_offsets = set()

    while True:
        if offset >= len(buf):
            raise ValueError(f"Offset {offset} out of bounds (buf len {len(buf)})")
        length = buf[offset]
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(buf):
                raise ValueError("Incomplete compression pointer")
            pointer = ((length & 0x3F) << 8) | buf[offset + 1]
            if pointer in visited_offsets:
                raise ValueError(f"Compression loop detected at offset {pointer}")
            visited_offsets.add(pointer)
            if not jumped:
                original_offset = offset + 2
                jumped = True
            offset = pointer
        elif length == 0:
            offset += 1
            break
        else:
            offset += 1
            if offset + length > len(buf):
                raise ValueError("Label length exceeds buffer boundary")
            labels.append(buf[offset:offset + length].decode("ascii", errors="replace"))
            offset += length

    domain = ".".join(labels) + "." if labels else "."
    return domain, (original_offset if jumped else offset)


def build_dns_query(pkt_id: int, domain: str, qtype: int = 1, rd: bool = False, opcode: int = 0) -> bytes:
    """Build a standard 1-question DNS query packet."""
    flags = (
        (0 << 15)            # QR: 0 (Query)
        | ((opcode & 0xF) << 11)
        | (0 << 10)          # AA: 0
        | (0 << 9)           # TC: 0
        | ((1 if rd else 0) << 8) # RD
        | (0 << 7)           # RA: 0
        | (0 << 4)           # Z: 0
        | 0                  # RCODE: 0
    )
    header = struct.pack("!HHHHHH", pkt_id, flags, 1, 0, 0, 0)
    qname = encode_name(domain)
    question = qname + struct.pack("!HH", qtype, 1) # QTYPE, QCLASS=1 (IN)
    return header + question


def build_compressed_multi_query(pkt_id: int, domain1: str, domain2: str) -> bytes:
    """
    Build a multi-question query with domain compression identical to CodeCrafters stage 7:
    domain1 = "abc.longassdomainname.com."
    domain2 = "def.longassdomainname.com." (points to "longassdomainname.com." from domain1)
    """
    flags = 0  # QR=0, Opcode=0, etc.
    header = struct.pack("!HHHHHH", pkt_id, flags, 2, 0, 0, 0)
    
    # Question 1: \x03abc\x12longassdomainname\x03com\x00
    # Header is 12 bytes. Offset 12 is \x03abc.
    # Offset 16 is \x12longassdomainname\x03com\x00
    q1_name = encode_name(domain1)
    q1 = q1_name + struct.pack("!HH", 1, 1) # A, IN
    
    # Question 2: \x03def + pointer to offset 16 (0xC010)
    q2_prefix = bytes([3]) + b"def"
    pointer_offset = 12 + 1 + 3  # 16
    q2_name = q2_prefix + struct.pack("!H", 0xC000 | pointer_offset)
    q2 = q2_name + struct.pack("!HH", 1, 1) # A, IN
    
    return header + q1 + q2


def parse_dns_packet(buf: bytes):
    """Parse a DNS response packet into a structured dictionary."""
    if len(buf) < 12:
        raise ValueError(f"Packet too short ({len(buf)} bytes, minimum 12 bytes required for DNS header)")

    pkt_id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHHHH", buf, 0)
    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 0x1
    tc = (flags >> 9) & 0x1
    rd = (flags >> 8) & 0x1
    ra = (flags >> 7) & 0x1
    z = (flags >> 4) & 0x7
    rcode = flags & 0xF

    offset = 12
    questions = []
    for _ in range(qdcount):
        qname, offset = decode_name(buf, offset)
        qtype, qclass = struct.unpack_from("!HH", buf, offset)
        offset += 4
        questions.append({"name": qname, "qtype": qtype, "qclass": qclass})

    answers = []
    for _ in range(ancount):
        aname, offset = decode_name(buf, offset)
        atype, aclass, attl, rdlength = struct.unpack_from("!HHIH", buf, offset)
        offset += 10
        rdata = buf[offset:offset + rdlength]
        offset += rdlength
        ip_str = ""
        if atype == 1 and rdlength == 4:
            ip_str = socket.inet_ntoa(rdata)
        answers.append({
            "name": aname,
            "type": atype,
            "class": aclass,
            "ttl": attl,
            "rdata": rdata,
            "ip": ip_str,
        })

    return {
        "id": pkt_id,
        "qr": qr,
        "opcode": opcode,
        "aa": aa,
        "tc": tc,
        "rd": rd,
        "ra": ra,
        "z": z,
        "rcode": rcode,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
        "questions": questions,
        "answers": answers,
        "raw_len": len(buf)
    }

# ----------------- Mock Upstream Resolver Server -----------------

class MockResolverServer:
    """Runs a mock upstream DNS server on 127.0.0.1:5354 matching dns_resolver.go."""
    def __init__(self, addr=("127.0.0.1", 5354)):
        self.addr = addr
        self.sock = None
        self.running = False
        self.thread = None

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.addr)
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while self.running:
            try:
                self.sock.settimeout(0.5)
                data, addr = self.sock.recvfrom(2048)
                if not data:
                    continue
                req = parse_dns_packet(data)
                answers = []
                for q in req["questions"]:
                    domain = q["name"]
                    qtype = q["qtype"]
                    if domain in DNS_RECORDS and qtype in DNS_RECORDS[domain]:
                        val = DNS_RECORDS[domain][qtype]
                        if qtype == 1:
                            rdata = socket.inet_aton(val)
                            answers.append((domain, qtype, 1, 60, rdata))

                # Build response packet
                resp_flags = (
                    (1 << 15)  # QR=1
                    | ((req["opcode"] & 0xF) << 11)
                    | (0 << 10) # AA=0
                    | (0 << 9)  # TC=0
                    | ((req["rd"] & 0x1) << 8)
                    | (1 << 7)  # RA=1
                    | 0         # RCODE=0
                )
                header = struct.pack("!HHHHHH", req["id"], resp_flags, len(req["questions"]), len(answers), 0, 0)
                body = b""
                for q in req["questions"]:
                    body += encode_name(q["name"]) + struct.pack("!HH", q["qtype"], q["qclass"])
                for aname, atype, aclass, attl, rdata in answers:
                    body += encode_name(aname) + struct.pack("!HHIH", atype, aclass, attl, len(rdata)) + rdata

                self.sock.sendto(header + body, addr)
            except socket.timeout:
                continue
            except Exception:
                if not self.running:
                    break

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        if self.thread:
            self.thread.join(timeout=1.0)

# ----------------- Server Process Lifecycle -----------------

def locate_main_py():
    """Locate the target app/main.py relative to current script or working directory."""
    candidates = [
        os.path.join(os.path.dirname(__file__), "app", "main.py"),
        os.path.join(os.getcwd(), "app", "main.py"),
        os.path.join(os.getcwd(), "Building-my-own-DNS-Server", "app", "main.py"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return os.path.abspath(c)
    raise FileNotFoundError("Could not find app/main.py. Ensure your project has app/main.py.")


def start_user_server(resolver_arg="127.0.0.1:5354"):
    """Start the user's DNS server as a subprocess with --resolver."""
    target_py = locate_main_py()
    cmd = [sys.executable, "-u", target_py, "--resolver", resolver_arg]
    cwd = os.path.dirname(os.path.dirname(target_py))
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    time.sleep(0.4) # Give the server a moment to bind UDP port 2053
    return proc, " ".join(cmd)


def terminate_server(proc):
    """Terminate the server process and capture outputs."""
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    stdout, stderr = proc.communicate()
    return stdout, stderr, proc.returncode

# ----------------- Client UDP Exchange -----------------

def send_udp_query(data: bytes, timeout=2.0) -> bytes:
    """Send raw UDP bytes to 127.0.0.1:2053 and return response."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(data, SERVER_ADDR)
        resp, _ = s.recvfrom(2048)
        return resp

# ----------------- Challenge Stages Definition -----------------

STAGES = [
    {
        "id": "ux2",
        "numeric_id": "1",
        "name": "Setup UDP server",
        "description": "Start a UDP server listening on port 2053 and respond to incoming packets.",
    },
    {
        "id": "tz1",
        "numeric_id": "2",
        "name": "Write header section",
        "description": "Respond with a valid 12-byte DNS header (QR=1, AA=0, matching ID).",
    },
    {
        "id": "bf2",
        "numeric_id": "3",
        "name": "Write question section",
        "description": "Include 1 question section in the response matching the query domain (Type A, Class IN).",
    },
    {
        "id": "xm2",
        "numeric_id": "4",
        "name": "Write answer section",
        "description": "Include at least 1 answer record with domain name and valid IPv4 address.",
    },
    {
        "id": "uc8",
        "numeric_id": "5",
        "name": "Parse header section",
        "description": "Echo RD and Opcode; return RCODE=4 if Opcode != 0, else RCODE=0.",
    },
    {
        "id": "hd8",
        "numeric_id": "6",
        "name": "Parse question section",
        "description": "Dynamically parse question domain and return matching answer section.",
    },
    {
        "id": "yc9",
        "numeric_id": "7",
        "name": "Parse compressed packet",
        "description": "Parse compressed multi-question packet and return 2 corresponding answers.",
    },
    {
        "id": "gt1",
        "numeric_id": "8",
        "name": "Forwarding Server",
        "description": "Forward DNS queries to upstream resolver (--resolver) and return resolved answer.",
    },
]

# ----------------- Stage Test Implementations -----------------

def run_test_ux2(proc):
    """Stage 1 (ux2): Setup UDP server."""
    query = build_dns_query(DEFAULT_PKT_ID, DEFAULT_DOMAIN, qtype=1)
    # Retry communication up to 5 times like the original tester
    last_err = None
    for attempt in range(5):
        if proc.poll() is not None:
            raise RuntimeError("Program terminated early. A DNS server is expected to be a long-running process.")
        try:
            resp = send_udp_query(query, timeout=1.0)
            # In stage 1, any response (even empty response b"") is accepted as long as server runs
            return f"Received response of {len(resp)} bytes from DNS server without error."
        except socket.timeout as e:
            last_err = e
            time.sleep(0.5)
        except Exception as e:
            last_err = e
            time.sleep(0.5)
    raise RuntimeError(f"Did not receive response from DNS server on port 2053: {last_err}")


def run_test_tz1(proc):
    """Stage 2 (tz1): Write header section."""
    query = build_dns_query(DEFAULT_PKT_ID, DEFAULT_DOMAIN, qtype=1)
    resp_raw = send_udp_query(query, timeout=2.0)
    parsed = parse_dns_packet(resp_raw)
    
    if parsed["id"] != DEFAULT_PKT_ID:
        raise AssertionError(f"Expected packet ID to match request ({DEFAULT_PKT_ID}), got {parsed['id']}")
    if parsed["qr"] != 1:
        raise AssertionError(f"Expected QR field to be set to 1 (response), got {parsed['qr']}")
    if parsed["aa"] != 0:
        raise AssertionError(f"Expected AA field to not be set (0), got {parsed['aa']}")
    if parsed["tc"] != 0:
        raise AssertionError(f"Expected TC field to be 0, got {parsed['tc']}")
    if parsed["ra"] != 0:
        raise AssertionError(f"Expected RA field to be 0, got {parsed['ra']}")
    if parsed["rcode"] != 0:
        raise AssertionError(f"Expected RCODE to be 0, got {parsed['rcode']}")
    return f"Header valid (ID={parsed['id']}, QR=1, AA=0, RCODE=0, Raw={parsed['raw_len']} bytes)"


def run_test_bf2(proc):
    """Stage 3 (bf2): Write question section."""
    query = build_dns_query(DEFAULT_PKT_ID, DEFAULT_DOMAIN, qtype=1)
    resp_raw = send_udp_query(query, timeout=2.0)
    parsed = parse_dns_packet(resp_raw)

    if parsed["qr"] != 1:
        raise AssertionError(f"Expected QR field to be 1, got {parsed['qr']}")
    if parsed["aa"] != 0:
        raise AssertionError(f"Expected AA field to be 0, got {parsed['aa']}")
    if len(parsed["questions"]) != 1:
        raise AssertionError(f"Expected exactly 1 question in response, got {len(parsed['questions'])}")

    q = parsed["questions"][0]
    if q["name"] != DEFAULT_DOMAIN:
        raise AssertionError(f"Expected question domain `{DEFAULT_DOMAIN}`, got `{q['name']}`")
    if q["qtype"] != 1:
        raise AssertionError(f"Expected question type 1 (A), got {q['qtype']}")
    if q["qclass"] != 1:
        raise AssertionError(f"Expected question class 1 (IN), got {q['qclass']}")
    return f"Question section valid ({q['name']} IN A)"


def run_test_xm2(proc):
    """Stage 4 (xm2): Write answer section."""
    query = build_dns_query(DEFAULT_PKT_ID, DEFAULT_DOMAIN, qtype=1)
    resp_raw = send_udp_query(query, timeout=2.0)
    parsed = parse_dns_packet(resp_raw)

    if len(parsed["questions"]) == 0:
        raise AssertionError("Expected question section to be present in response")
    if len(parsed["answers"]) == 0:
        raise AssertionError(f"Expected at least one entry in answer section, got {len(parsed['answers'])}")

    ans = parsed["answers"][0]
    if ans["name"] != DEFAULT_DOMAIN:
        raise AssertionError(f"Expected answer domain name `{DEFAULT_DOMAIN}`, got `{ans['name']}`")
    if ans["type"] != 1:
        raise AssertionError(f"Expected answer record type 1 (A), got {ans['type']}")
    if not ans["ip"]:
        raise AssertionError(f"Expected valid IPv4 address in answer record, got RDATA length {len(ans['rdata'])}")
    return f"Answer section valid: {ans['name']} -> {ans['ip']}"


def run_test_uc8(proc):
    """Stage 5 (uc8): Parse header section."""
    for rd in [True, False]:
        for opcode in range(4):
            pkt_id = random.randint(1000, 60000)
            query = build_dns_query(pkt_id, DEFAULT_DOMAIN, qtype=1, rd=rd, opcode=opcode)
            resp_raw = send_udp_query(query, timeout=2.0)
            parsed = parse_dns_packet(resp_raw)

            if parsed["qr"] != 1:
                raise AssertionError(f"Expected QR=1, got {parsed['qr']}")
            if parsed["aa"] != 0:
                raise AssertionError(f"Expected AA=0, got {parsed['aa']}")
            if parsed["rd"] != (1 if rd else 0):
                raise AssertionError(f"Expected RecursionDesired={rd}, got {parsed['rd']}")
            if parsed["opcode"] != opcode:
                raise AssertionError(f"Expected Opcode={opcode}, got {parsed['opcode']}")
            if opcode != 0 and parsed["rcode"] != 4:
                raise AssertionError(f"Expected Rcode=4 (Not Implemented) for Opcode={opcode}, got {parsed['rcode']}")
            if opcode == 0 and parsed["rcode"] != 0:
                raise AssertionError(f"Expected Rcode=0 for Opcode 0, got {parsed['rcode']}")
    return "All RD and Opcode combinations correctly parsed and echoed"


def run_test_hd8(proc):
    """Stage 6 (hd8): Parse question section."""
    # Pick a random domain
    domains = [d for d, records in DNS_RECORDS.items() if 1 in records]
    query_domain = random.choice(domains)
    pkt_id = random.randint(1000, 60000)

    query = build_dns_query(pkt_id, query_domain, qtype=1)
    resp_raw = send_udp_query(query, timeout=2.0)
    parsed = parse_dns_packet(resp_raw)

    if len(parsed["answers"]) == 0:
        raise AssertionError("Expected answer section to have at least one entry")

    for record in parsed["answers"]:
        if record["name"] != query_domain:
            raise AssertionError(f"Expected answer domain name `{query_domain}`, got `{record['name']}`")
        if record["type"] != 1:
            raise AssertionError(f"Expected answer type 1 (A), got {record['type']}")
        if not record["ip"]:
            raise AssertionError("Expected answer record to contain valid IPv4 address")

    return f"Correctly parsed question domain `{query_domain}` and responded with valid A record"


def run_test_yc9(proc):
    """Stage 7 (yc9): Parse compressed packet."""
    domain1 = "abc.longassdomainname.com."
    domain2 = "def.longassdomainname.com."
    pkt_id = random.randint(1000, 60000)

    query = build_compressed_multi_query(pkt_id, domain1, domain2)
    resp_raw = send_udp_query(query, timeout=2.0)
    parsed = parse_dns_packet(resp_raw)

    if len(parsed["answers"]) != 2:
        raise AssertionError(f"Expected 2 entries in answer section, got {len(parsed['answers'])}")

    expected_domains = [domain1, domain2]
    for i, record in enumerate(parsed["answers"]):
        exp = expected_domains[i]
        if record["name"] != exp:
            raise AssertionError(f"Expected answer {i} domain `{exp}`, got `{record['name']}`")
        if record["type"] != 1:
            raise AssertionError(f"Expected answer {i} type 1 (A), got {record['type']}")

    return f"Successfully decompressed packet and returned 2 answers for `{domain1}` and `{domain2}`"


def run_test_gt1(proc):
    """Stage 8 (gt1): Forwarding Server."""
    domains = [d for d, records in DNS_RECORDS.items() if 1 in records]
    query_domain = random.choice(domains)
    expected_ip = DNS_RECORDS[query_domain][1]
    pkt_id = random.randint(1000, 60000)

    query = build_dns_query(pkt_id, query_domain, qtype=1)
    resp_raw = send_udp_query(query, timeout=2.0)
    parsed = parse_dns_packet(resp_raw)

    matched = False
    for record in parsed["answers"]:
        if record["name"] == query_domain and record["type"] == 1:
            if record["ip"] == expected_ip:
                matched = True
                break
            else:
                raise AssertionError(f"Expected IPv4 address `{expected_ip}` for `{query_domain}`, got `{record['ip']}`")

    if not matched:
        raise AssertionError(f"Expected resolved IPv4 address `{expected_ip}` for `{query_domain}`. No match found.")

    return f"Successfully forwarded query to upstream resolver and returned `{expected_ip}`"


STAGE_TEST_FUNCS = {
    "ux2": run_test_ux2,
    "tz1": run_test_tz1,
    "bf2": run_test_bf2,
    "xm2": run_test_xm2,
    "uc8": run_test_uc8,
    "hd8": run_test_hd8,
    "yc9": run_test_yc9,
    "gt1": run_test_gt1,
}

# ----------------- Execution Engine & Reporting -----------------

def execute_stage(stage_info):
    """Execute a single challenge stage and return structured result."""
    stage_id = stage_info["id"]
    stage_name = stage_info["name"]
    test_func = STAGE_TEST_FUNCS.get(stage_id)

    # Start mock resolver on 127.0.0.1:5354
    resolver = MockResolverServer()
    resolver.start()

    proc = None
    cmd_str = ""
    status = "FAIL"
    expected_result = stage_info["description"]
    actual_result = ""
    exit_code_str = ""
    failure_reason = ""

    try:
        proc, cmd_str = start_user_server(resolver_arg="127.0.0.1:5354")
        success_msg = test_func(proc)
        status = "PASS"
        actual_result = success_msg
        exit_code_str = "0 (Running)"
    except Exception as e:
        status = "FAIL"
        actual_result = f"Error: {e}"
        failure_reason = str(e)
        if proc and proc.poll() is not None:
            exit_code_str = f"{proc.poll()} (Terminated prematurely)"
        else:
            exit_code_str = "N/A (Failed during test execution)"
    finally:
        if proc:
            stdout, stderr, code = terminate_server(proc)
            if status != "PASS" and (stdout or stderr):
                logs = (stdout + "\n" + stderr).strip()
                if logs:
                    failure_reason += f"\nServer Output:\n{logs}"
        resolver.stop()

    print(f"Challenge: {CHALLENGE_NAME}")
    print(f"Step ID: {stage_id}")
    print(f"Step Name: {stage_name}")
    print(f"Command: {cmd_str}")
    print(f"Expected Result: {expected_result}")
    print(f"Actual Result: {actual_result}")
    print(f"Exit Code: {exit_code_str}")
    print(f"Status: {status}")
    if failure_reason:
        print(f"Failure Reason: {failure_reason}")
    print("-" * 60)

    return status


def main():
    parser = argparse.ArgumentParser(description="CodeCrafters 'Build your own DNS server' Test Runner")
    parser.add_argument("--list", action="store_true", help="Display all available challenge test steps")
    parser.add_argument("--id", type=str, help="Execute a test using its original step ID or numeric index (1-8)")
    parser.add_argument("--step", type=str, help="Execute a test using its original step name")
    parser.add_argument("--all", action="store_true", help="Execute all available tests in the original challenge order")

    args = parser.parse_args()

    if args.list:
        print(f"\nChallenge: {CHALLENGE_NAME}")
        print("Available Challenge Steps:")
        print(f"{'#':<4} {'Step ID':<10} {'Step Name':<30} {'Description'}")
        print("-" * 80)
        for s in STAGES:
            print(f"{s['numeric_id']:<4} {s['id']:<10} {s['name']:<30} {s['description']}")
        print()
        return

    stages_to_run = []
    if args.id:
        target = args.id.strip().lower()
        matched = [s for s in STAGES if s["id"].lower() == target or s["numeric_id"] == target]
        if not matched:
            print(f"Error: Step ID '{args.id}' not found. Run with --list to see available steps.", file=sys.stderr)
            sys.exit(1)
        stages_to_run = matched
    elif args.step:
        target = args.step.strip().lower()
        matched = [s for s in STAGES if s["name"].lower() == target]
        if not matched:
            print(f"Error: Step name '{args.step}' not found. Run with --list to see available steps.", file=sys.stderr)
            sys.exit(1)
        stages_to_run = matched
    elif args.all:
        stages_to_run = STAGES
    else:
        parser.print_help()
        sys.exit(1)

    total_discovered = len(STAGES)
    executed = 0
    passed = 0
    failed = 0
    skipped = 0

    stop_on_fail = args.all
    skip_remaining = False

    print(f"\nRunning tests for '{CHALLENGE_NAME}'...\n" + "=" * 60)

    for stage in stages_to_run:
        if skip_remaining:
            print(f"Challenge: {CHALLENGE_NAME}")
            print(f"Step ID: {stage['id']}")
            print(f"Step Name: {stage['name']}")
            print("Command: None")
            print(f"Expected Result: {stage['description']}")
            print("Actual Result: Not executed due to previous step failure")
            print("Exit Code: N/A")
            print("Status: SKIPPED")
            print(f"Failure Reason: Prerequisite step failed")
            print("-" * 60)
            skipped += 1
            continue

        executed += 1
        res = execute_stage(stage)
        if res == "PASS":
            passed += 1
        else:
            failed += 1
            if stop_on_fail:
                skip_remaining = True

    # Account for stages not in selection if running a subset
    if not args.all:
        skipped = total_discovered - executed

    print("\n" + "=" * 60)
    print("Test Execution Summary:")
    print(f"- Total tests discovered: {total_discovered}")
    print(f"- Total tests executed: {executed}")
    print(f"- Passed tests: {passed}")
    print(f"- Failed tests: {failed}")
    print(f"- Skipped tests: {skipped}")
    print(f"- Tests unavailable from the public repository: 0")
    print("=" * 60 + "\n")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
