import os
import threading
import time
from datetime import datetime, timezone
from io import BytesIO

from flask import Flask, jsonify, request
from flask_cors import CORS
from scapy.all import (
    ARP, Ether, ICMP, IP, IPv6, TCP, UDP, Dot1Q, Raw,
    rdpcap, sniff, get_if_list
)

app = Flask(__name__)
CORS(app)

MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(50 * 1024 * 1024)))
MAX_FRAMES = int(os.getenv("MAX_FRAMES", "5000"))

capture_lock = threading.Lock()
capture_state = {
    "running": False,
    "interface": None,
    "started_at": None,
    "frames": [],
    "error": None,
    "stop_event": None,
    "thread": None,
}


def hex_ascii(data: bytes):
    return {
        "hex": data.hex(" ") if data else "",
        "ascii": "".join(chr(b) if 32 <= b <= 126 else "." for b in data),
        "length": len(data),
    }


def field(name, value, offset, size, description=""):
    return {
        "name": name,
        "value": value,
        "offset": offset,
        "size": size,
        "description": description,
    }


def timestamp_for(packet):
    try:
        return datetime.fromtimestamp(float(packet.time), tz=timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def analyze_packet(packet, frame_number=1):
    raw = bytes(packet)
    cap_len = len(raw)
    layers = []
    fields = []
    protocol_stack = []
    notes = []
    cursor = 0
    payload_start = 0
    fcs_info = {
        "present": False,
        "length": 0,
        "value": None,
        "verification": "not available in capture",
    }

    # Ethernet header
    if not packet.haslayer(Ether):
        return {
            "frame_number": frame_number,
            "timestamp": timestamp_for(packet),
            "captured_length": cap_len,
            "original_length": cap_len,
            "protocol_stack": ["Unsupported link-layer frame"],
            "summary": "Frame does not contain a recognized Ethernet header.",
            "layers": [],
            "fields": [],
            "raw_data": hex_ascii(raw),
            "trailer_fcs": fcs_info,
            "warnings": ["Only Ethernet II / Ethernet frames are supported by this initial backend."],
        }

    eth = packet[Ether]
    dst = eth.dst
    src = eth.src
    type_or_length = int(eth.type)
    eth_fields = [
        field("Destination MAC", dst, 0, 6, "Destination hardware address"),
        field("Source MAC", src, 6, 6, "Source hardware address"),
        field("Type/Length", f"0x{type_or_length:04x}", 12, 2,
              "EtherType when value is at least 1536; otherwise IEEE 802.3 length"),
    ]
    fields.extend(eth_fields)
    cursor = 14
    protocol_stack.append("Ethernet")
    layers.append({
        "name": "Ethernet",
        "pdu": "Frame",
        "header": {"offset": 0, "length": 14, "bytes": hex_ascii(raw[:14])},
        "payload": None,
        "trailer": {"status": "not available in capture"},
        "fields": eth_fields,
    })

    # VLAN tag(s), if present
    vlan_layers = packet.getlayer(Dot1Q)
    if vlan_layers:
        # Scapy's decoded Dot1Q layer starts after the Ethernet 14-byte header.
        vlan = vlan_layers
        vlan_fields = [
            field("VLAN Priority (PCP)", int(vlan.prio), 14, 1, "802.1Q priority bits"),
            field("Drop Eligible Indicator (DEI)", int(vlan.id) >> 12 if hasattr(vlan, "id") else 0, 14, 1, "VLAN drop eligibility"),
            field("VLAN ID", int(vlan.vlan), 14, 2, "802.1Q VLAN identifier"),
            field("Inner EtherType", f"0x{int(vlan.type):04x}", 16, 2, "Protocol encapsulated by VLAN tag"),
        ]
        fields.extend(vlan_fields)
        layers.append({
            "name": "802.1Q VLAN",
            "pdu": "Tag",
            "header": {"offset": 14, "length": 4, "bytes": hex_ascii(raw[14:18])},
            "payload": None,
            "trailer": None,
            "fields": vlan_fields,
        })
        protocol_stack.append(f"VLAN {int(vlan.vlan)}")
        cursor = 18
        type_or_length = int(vlan.type)

    network_payload_start = cursor
    transport_payload_start = None
    app_payload_start = None
    app_payload_end = cap_len
    summary_parts = []

    if packet.haslayer(ARP):
        arp = packet[ARP]
        protocol_stack.append("ARP")
        arp_fields = [
            field("Hardware type", int(arp.hwtype), cursor, 2, "Link-layer type"),
            field("Protocol type", f"0x{int(arp.ptype):04x}", cursor + 2, 2, "Network protocol being mapped"),
            field("Hardware address length", int(arp.hwlen), cursor + 4, 1, "Length of hardware address"),
            field("Protocol address length", int(arp.plen), cursor + 5, 1, "Length of protocol address"),
            field("Operation", "request" if int(arp.op) == 1 else "reply" if int(arp.op) == 2 else int(arp.op), cursor + 6, 2, "ARP operation"),
            field("Sender MAC", arp.hwsrc, cursor + 8, 6, "Sender hardware address"),
            field("Sender IP", arp.psrc, cursor + 14, 4, "Sender protocol address"),
            field("Target MAC", arp.hwdst, cursor + 18, 6, "Target hardware address"),
            field("Target IP", arp.pdst, cursor + 24, 4, "Target protocol address"),
        ]
        fields.extend(arp_fields)
        arp_len = 28
        layers.append({
            "name": "ARP",
            "pdu": "Message",
            "header": {"offset": cursor, "length": arp_len, "bytes": hex_ascii(raw[cursor:cursor + arp_len])},
            "payload": {"offset": cursor + arp_len, **hex_ascii(raw[cursor + arp_len:])},
            "trailer": None,
            "fields": arp_fields,
        })
        summary_parts.append(f"ARP {'request' if int(arp.op) == 1 else 'reply'} from {arp.psrc} to {arp.pdst}")
        app_payload_start = cursor + arp_len

    elif packet.haslayer(IP):
        ip = packet[IP]
        protocol_stack.append("IPv4")
        ihl = int(ip.ihl or 5) * 4
        ip_total_len = int(ip.len or max(0, cap_len - cursor))
        ip_end = min(cap_len, cursor + ip_total_len)
        ip_fields = [
            field("Version", int(ip.version), cursor, 1, "IP version"),
            field("IHL", int(ip.ihl or 5), cursor, 1, "Header length in 32-bit words"),
            field("DSCP/ECN", int(ip.tos), cursor + 1, 1, "Differentiated services and congestion notification"),
            field("Total Length", ip_total_len, cursor + 2, 2, "IPv4 header plus payload length"),
            field("Identification", int(ip.id), cursor + 4, 2, "Fragment identification"),
            field("Flags", str(ip.flags), cursor + 6, 1, "Fragmentation flags"),
            field("Fragment Offset", int(ip.frag), cursor + 6, 2, "Fragment offset"),
            field("TTL", int(ip.ttl), cursor + 8, 1, "Time to live"),
            field("Protocol", int(ip.proto), cursor + 9, 1, "1=ICMP, 6=TCP, 17=UDP"),
            field("Header Checksum", f"0x{int(ip.chksum or 0):04x}", cursor + 10, 2, "IPv4 header checksum"),
            field("Source IP", ip.src, cursor + 12, 4, "Source IPv4 address"),
            field("Destination IP", ip.dst, cursor + 16, 4, "Destination IPv4 address"),
        ]
        if ihl > 20:
            ip_fields.append(field("Options", raw[cursor + 20:cursor + ihl].hex(" "), cursor + 20, ihl - 20, "Optional IPv4 header bytes"))
        fields.extend(ip_fields)
        layers.append({
            "name": "IPv4",
            "pdu": "Packet",
            "header": {"offset": cursor, "length": ihl, "bytes": hex_ascii(raw[cursor:min(cursor + ihl, cap_len)])},
            "payload": {"offset": cursor + ihl, **hex_ascii(raw[cursor + ihl:ip_end])},
            "trailer": None,
            "fields": ip_fields,
        })
        summary_parts.append(f"IPv4 {ip.src} → {ip.dst}")
        transport_cursor = cursor + ihl
        transport_end = ip_end

        # Transport parsers
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            thl = int(tcp.dataofs or 5) * 4
            protocol_stack.append("TCP")
            tcp_fields = [
                field("Source Port", int(tcp.sport), transport_cursor, 2, "Sending application port"),
                field("Destination Port", int(tcp.dport), transport_cursor + 2, 2, "Receiving application port"),
                field("Sequence Number", int(tcp.seq), transport_cursor + 4, 4, "TCP sequence number"),
                field("Acknowledgement Number", int(tcp.ack), transport_cursor + 8, 4, "TCP acknowledgement number"),
                field("Data Offset", int(tcp.dataofs or 5), transport_cursor + 12, 1, "TCP header length in 32-bit words"),
                field("Flags", str(tcp.flags), transport_cursor + 13, 1, "TCP control flags"),
                field("Window Size", int(tcp.window), transport_cursor + 14, 2, "Advertised receive window"),
                field("Checksum", f"0x{int(tcp.chksum or 0):04x}", transport_cursor + 16, 2, "TCP checksum"),
                field("Urgent Pointer", int(tcp.urgptr), transport_cursor + 18, 2, "Urgent pointer"),
            ]
            fields.extend(tcp_fields)
            layers.append({
                "name": "TCP",
                "pdu": "Segment",
                "header": {"offset": transport_cursor, "length": thl, "bytes": hex_ascii(raw[transport_cursor:min(transport_cursor + thl, transport_end)])},
                "payload": {"offset": transport_cursor + thl, **hex_ascii(raw[min(transport_cursor + thl, transport_end):transport_end])},
                "trailer": None,
                "fields": tcp_fields,
            })
            app_payload_start = min(transport_cursor + thl, transport_end)
            summary_parts.append(f"TCP {tcp.sport} → {tcp.dport} flags={tcp.flags}")

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            protocol_stack.append("UDP")
            udp_len = int(udp.len or max(8, transport_end - transport_cursor))
            udp_end = min(transport_end, transport_cursor + udp_len)
            udp_fields = [
                field("Source Port", int(udp.sport), transport_cursor, 2, "Sending application port"),
                field("Destination Port", int(udp.dport), transport_cursor + 2, 2, "Receiving application port"),
                field("Length", udp_len, transport_cursor + 4, 2, "UDP header plus data length"),
                field("Checksum", f"0x{int(udp.chksum or 0):04x}", transport_cursor + 6, 2, "UDP checksum"),
            ]
            fields.extend(udp_fields)
            layers.append({
                "name": "UDP",
                "pdu": "Datagram",
                "header": {"offset": transport_cursor, "length": 8, "bytes": hex_ascii(raw[transport_cursor:min(transport_cursor + 8, udp_end)])},
                "payload": {"offset": transport_cursor + 8, **hex_ascii(raw[min(transport_cursor + 8, udp_end):udp_end])},
                "trailer": None,
                "fields": udp_fields,
            })
            app_payload_start = min(transport_cursor + 8, udp_end)
            summary_parts.append(f"UDP {udp.sport} → {udp.dport}")

        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            protocol_stack.append("ICMP")
            icmp_fields = [
                field("Type", int(icmp.type), transport_cursor, 1, "ICMP message type"),
                field("Code", int(icmp.code), transport_cursor + 1, 1, "ICMP message subtype"),
                field("Checksum", f"0x{int(icmp.chksum or 0):04x}", transport_cursor + 2, 2, "ICMP checksum"),
            ]
            fields.extend(icmp_fields)
            layers.append({
                "name": "ICMP",
                "pdu": "Message",
                "header": {"offset": transport_cursor, "length": 4, "bytes": hex_ascii(raw[transport_cursor:min(transport_cursor + 4, transport_end)])},
                "payload": {"offset": min(transport_cursor + 4, transport_end), **hex_ascii(raw[min(transport_cursor + 4, transport_end):transport_end])},
                "trailer": None,
                "fields": icmp_fields,
            })
            app_payload_start = min(transport_cursor + 4, transport_end)
            summary_parts.append(f"ICMP type {icmp.type} code {icmp.code}")
        else:
            app_payload_start = transport_cursor
            if int(ip.proto) not in (1, 6, 17):
                notes.append(f"IPv4 protocol number {int(ip.proto)} is not decoded by this backend.")

    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        protocol_stack.append("IPv6")
        payload_len = int(ip6.plen or max(0, cap_len - cursor - 40))
        ip6_end = min(cap_len, cursor + 40 + payload_len)
        ip6_fields = [
            field("Version", int(ip6.version), cursor, 1, "IP version"),
            field("Traffic Class", int(ip6.tc), cursor, 2, "Traffic class"),
            field("Flow Label", int(ip6.fl), cursor + 1, 3, "Flow label"),
            field("Payload Length", payload_len, cursor + 4, 2, "Bytes after the fixed IPv6 header"),
            field("Next Header", int(ip6.nh), cursor + 6, 1, "Next protocol or extension header"),
            field("Hop Limit", int(ip6.hlim), cursor + 7, 1, "IPv6 hop limit"),
            field("Source IP", ip6.src, cursor + 8, 16, "Source IPv6 address"),
            field("Destination IP", ip6.dst, cursor + 24, 16, "Destination IPv6 address"),
        ]
        fields.extend(ip6_fields)
        layers.append({
            "name": "IPv6",
            "pdu": "Packet",
            "header": {"offset": cursor, "length": 40, "bytes": hex_ascii(raw[cursor:min(cursor + 40, cap_len)])},
            "payload": {"offset": cursor + 40, **hex_ascii(raw[min(cursor + 40, cap_len):ip6_end])},
            "trailer": None,
            "fields": ip6_fields,
        })
        summary_parts.append(f"IPv6 {ip6.src} → {ip6.dst}")
        transport_cursor = cursor + 40
        transport_end = ip6_end

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            thl = int(tcp.dataofs or 5) * 4
            protocol_stack.append("TCP")
            tcp_fields = [
                field("Source Port", int(tcp.sport), transport_cursor, 2, "Sending application port"),
                field("Destination Port", int(tcp.dport), transport_cursor + 2, 2, "Receiving application port"),
                field("Sequence Number", int(tcp.seq), transport_cursor + 4, 4, "TCP sequence number"),
                field("Acknowledgement Number", int(tcp.ack), transport_cursor + 8, 4, "TCP acknowledgement number"),
                field("Data Offset", int(tcp.dataofs or 5), transport_cursor + 12, 1, "TCP header length in 32-bit words"),
                field("Flags", str(tcp.flags), transport_cursor + 13, 1, "TCP control flags"),
                field("Window Size", int(tcp.window), transport_cursor + 14, 2, "Advertised receive window"),
                field("Checksum", f"0x{int(tcp.chksum or 0):04x}", transport_cursor + 16, 2, "TCP checksum"),
            ]
            fields.extend(tcp_fields)
            layers.append({
                "name": "TCP", "pdu": "Segment",
                "header": {"offset": transport_cursor, "length": thl, "bytes": hex_ascii(raw[transport_cursor:min(transport_cursor + thl, transport_end)])},
                "payload": {"offset": min(transport_cursor + thl, transport_end), **hex_ascii(raw[min(transport_cursor + thl, transport_end):transport_end])},
                "trailer": None, "fields": tcp_fields,
            })
            app_payload_start = min(transport_cursor + thl, transport_end)
            summary_parts.append(f"TCP {tcp.sport} → {tcp.dport} flags={tcp.flags}")
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            protocol_stack.append("UDP")
            udp_fields = [
                field("Source Port", int(udp.sport), transport_cursor, 2, "Sending application port"),
                field("Destination Port", int(udp.dport), transport_cursor + 2, 2, "Receiving application port"),
                field("Length", int(udp.len or 8), transport_cursor + 4, 2, "UDP header plus data length"),
                field("Checksum", f"0x{int(udp.chksum or 0):04x}", transport_cursor + 6, 2, "UDP checksum"),
            ]
            fields.extend(udp_fields)
            layers.append({
                "name": "UDP", "pdu": "Datagram",
                "header": {"offset": transport_cursor, "length": 8, "bytes": hex_ascii(raw[transport_cursor:min(transport_cursor + 8, transport_end)])},
                "payload": {"offset": min(transport_cursor + 8, transport_end), **hex_ascii(raw[min(transport_cursor + 8, transport_end):transport_end])},
                "trailer": None, "fields": udp_fields,
            })
            app_payload_start = min(transport_cursor + 8, transport_end)
            summary_parts.append(f"UDP {udp.sport} → {udp.dport}")
        else:
            app_payload_start = transport_cursor
            notes.append(f"IPv6 next-header value {int(ip6.nh)} is not decoded by this backend.")
    else:
        protocol_stack.append("Unknown EtherType")
        notes.append(f"EtherType 0x{type_or_length:04x} is not decoded.")

    # Application/raw payload summary
    if app_payload_start is None:
        app_payload_start = network_payload_start
    app_payload_start = max(0, min(app_payload_start, cap_len))
    application_data = raw[app_payload_start:]
    layers.append({
        "name": "Application / Remaining Data",
        "pdu": "Data",
        "header": None,
        "payload": {"offset": app_payload_start, **hex_ascii(application_data)},
        "trailer": None,
        "fields": [],
    })

    # Captures generally omit FCS; do not infer the last four bytes are FCS.
    if cap_len < 14:
        notes.append("Frame is shorter than the minimum Ethernet header length.")
    if len(raw) != cap_len:
        notes.append("Captured length differs from raw byte length.")

    if not summary_parts:
        summary = " → ".join(protocol_stack)
    else:
        summary = "; ".join(summary_parts)
    if "TCP" in protocol_stack and packet.haslayer(TCP):
        tcp = packet[TCP]
        if "S" in str(tcp.flags) and "A" not in str(tcp.flags):
            summary += " (TCP SYN)"
    if notes:
        summary += " — " + " ".join(notes)

    return {
        "frame_number": frame_number,
        "timestamp": timestamp_for(packet),
        "captured_length": cap_len,
        "original_length": cap_len,
        "protocol_stack": protocol_stack,
        "summary": summary,
        "layers": layers,
        "fields": fields,
        "raw_data": hex_ascii(raw),
        "trailer_fcs": fcs_info,
        "warnings": notes,
    }


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "Network Traffic Framing Analyzer API"})


@app.get("/api/interfaces")
def interfaces():
    try:
        return jsonify({"interfaces": get_if_list()})
    except Exception as exc:
        return jsonify({"error": f"Could not list interfaces: {exc}"}), 500


@app.post("/api/analyze/hex")
def analyze_hex():
    body = request.get_json(silent=True) or {}
    hex_data = body.get("hex")
    if not isinstance(hex_data, str) or not hex_data.strip():
        return jsonify({"error": "Provide a non-empty 'hex' string in JSON."}), 400
    try:
        compact = "".join(hex_data.split()).replace(":", "").replace("-", "")
        raw = bytes.fromhex(compact)
        if len(raw) > MAX_UPLOAD_BYTES:
            return jsonify({"error": "Hex frame exceeds configured size limit."}), 413
        packet = Ether(raw)
        return jsonify({"frame": analyze_packet(packet)})
    except ValueError:
        return jsonify({"error": "Invalid hexadecimal input."}), 400
    except Exception as exc:
        return jsonify({"error": f"Could not analyze frame: {exc}"}), 400


@app.post("/api/analyze/pcap")
def analyze_pcap():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return jsonify({"error": "Upload a PCAP or PCAPNG file using the 'file' form field."}), 400
    content = upload.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        return jsonify({"error": f"File exceeds {MAX_UPLOAD_BYTES} byte upload limit."}), 413
    try:
        packets = rdpcap(BytesIO(content), count=MAX_FRAMES)
        frames = [analyze_packet(pkt, i + 1) for i, pkt in enumerate(packets)]
        return jsonify({
            "filename": upload.filename,
            "frame_count": len(frames),
            "truncated_to_limit": len(frames) >= MAX_FRAMES,
            "frames": frames,
        })
    except Exception as exc:
        return jsonify({"error": f"Could not read capture file: {exc}"}), 400


def capture_worker(interface, duration, packet_limit):
    try:
        packets = sniff(
            iface=interface,
            timeout=duration if duration > 0 else None,
            count=packet_limit if packet_limit > 0 else 0,
            store=True,
            stop_filter=lambda _: capture_state["stop_event"].is_set()
        )
        frames = [analyze_packet(pkt, i + 1) for i, pkt in enumerate(packets[:MAX_FRAMES])]
        with capture_lock:
            capture_state["frames"] = frames
    except Exception as exc:
        with capture_lock:
            capture_state["error"] = str(exc)
    finally:
        with capture_lock:
            capture_state["running"] = False
            capture_state["thread"] = None


@app.post("/api/capture/start")
def start_capture():
    body = request.get_json(silent=True) or {}
    interface = body.get("interface")
    if not interface:
        return jsonify({"error": "Provide an interface name from GET /api/interfaces."}), 400
    duration = int(body.get("duration_seconds", 30))
    packet_limit = int(body.get("packet_limit", 100))
    if duration < 0 or packet_limit < 0:
        return jsonify({"error": "duration_seconds and packet_limit must be non-negative."}), 400

    with capture_lock:
        if capture_state["running"]:
            return jsonify({"error": "A capture is already running."}), 409
        capture_state.update({
            "running": True,
            "interface": interface,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "frames": [],
            "error": None,
            "stop_event": threading.Event(),
        })
        thread = threading.Thread(
            target=capture_worker,
            args=(interface, duration, packet_limit),
            daemon=True
        )
        capture_state["thread"] = thread
        thread.start()
    return jsonify({"message": "Capture started.", "interface": interface}), 202


@app.post("/api/capture/stop")
def stop_capture():
    with capture_lock:
        if not capture_state["running"]:
            return jsonify({"message": "No capture is currently running."})
        event = capture_state.get("stop_event")
        if event:
            event.set()
    return jsonify({"message": "Stop requested. Poll GET /api/capture/status for results."})


@app.get("/api/capture/status")
def capture_status():
    with capture_lock:
        return jsonify({
            "running": capture_state["running"],
            "interface": capture_state["interface"],
            "started_at": capture_state["started_at"],
            "frame_count": len(capture_state["frames"]),
            "error": capture_state["error"],
        })


@app.get("/api/capture/frames")
def capture_frames():
    with capture_lock:
        return jsonify({"frame_count": len(capture_state["frames"]), "frames": capture_state["frames"]})


@app.get("/api/demo")
def demo():
    # A valid, small Ethernet/IPv4/TCP SYN frame for frontend development.
    from scapy.all import raw
    pkt = Ether(src="02:00:00:00:00:20", dst="02:00:00:00:00:30") / IP(
        src="192.168.1.20", dst="192.168.1.30", ttl=64
    ) / TCP(sport=51515, dport=80, flags="S", seq=1000)
    return jsonify({"frame": analyze_packet(Ether(raw(pkt)), 1)})


@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "Request is too large."}), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)
