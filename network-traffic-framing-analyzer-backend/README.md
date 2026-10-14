# Network Traffic Framing Analyzer — Backend

Backend for the BAITE203 Computer Networks and Data Communications Lab project. It provides a REST API for analyzing Ethernet frames and PCAP/PCAPNG captures.

## Features

- Analyze uploaded `.pcap` and `.pcapng` captures
- Analyze one Ethernet frame supplied as hexadecimal bytes
- Decode Ethernet, optional 802.1Q VLAN, ARP, IPv4, IPv6, TCP, UDP, and ICMP fields
- Show field offsets, sizes, header/payload bytes, hex and ASCII
- Explicitly report Ethernet FCS as **not available in capture** unless future capture metadata proves otherwise; it never assumes the last four bytes are FCS
- List local capture interfaces
- Optional live capture API (requires appropriate OS permissions and an interface you are authorized to monitor)
- Demo endpoint for frontend integration without a capture file

## Requirements

- Python 3.10 or newer recommended
- macOS, Linux, or Windows
- Live capture may require administrator/root privileges and packet capture support (Npcap on Windows; libpcap on macOS/Linux).

## Setup on macOS (Terminal)

```bash
cd network-traffic-framing-analyzer-backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

The API runs at `http://127.0.0.1:5000`.

If you get `externally-managed-environment`, make sure the virtual environment is activated before running `pip install`.

## API endpoints

### Health check
`GET /api/health`

### Demo frame
`GET /api/demo`

### List interfaces
`GET /api/interfaces`

### Analyze a PCAP/PCAPNG file
`POST /api/analyze/pcap`

Use `multipart/form-data` with the file field named `file`.

Example:
```bash
curl -X POST -F "file=@sample.pcap" http://127.0.0.1:5000/api/analyze/pcap
```

### Analyze hexadecimal frame bytes
`POST /api/analyze/hex`

JSON body:
```json
{
  "hex": "02 00 00 00 00 30 02 00 00 00 00 20 08 00"
}
```

The example above is only an Ethernet header and is too short to contain a complete network packet, but it can be used to test input validation and short-frame handling.

### Start live capture
`POST /api/capture/start`

JSON body:
```json
{
  "interface": "en0",
  "duration_seconds": 30,
  "packet_limit": 100
}
```

Use an interface name returned by `/api/interfaces`. Set `duration_seconds` or `packet_limit` to `0` for no limit on that dimension; stop the capture with the endpoint below. For a lab demo, it is safer to use a finite duration and packet limit.

### Stop live capture
`POST /api/capture/stop`

### Capture status
`GET /api/capture/status`

### Captured frames
`GET /api/capture/frames`

## Frontend integration

Base URL:
```js
const API_BASE = "http://127.0.0.1:5000";
```

Example: load the demo frame:
```js
const response = await fetch(`${API_BASE}/api/demo`);
const data = await response.json();
console.log(data.frame);
```

Example: upload a capture:
```js
const formData = new FormData();
formData.append("file", fileInput.files[0]);

const response = await fetch(`${API_BASE}/api/analyze/pcap`, {
  method: "POST",
  body: formData
});
const data = await response.json();
```

Do not manually set the `Content-Type` header when uploading `FormData`; the browser must add the multipart boundary.

## Important limitations

- Initial scope is Ethernet captures. Other link types are reported as unsupported.
- The FCS is commonly removed before packets reach the operating system. The API therefore reports FCS as unavailable unless it can be reliably identified from capture metadata; it does not guess.
- Live capture can fail if the interface does not exist, packet capture permissions are missing, or the host has no packet-capture driver installed.
- Promiscuous mode does not make a switched network reveal all other hosts' traffic. A correctly configured SPAN/mirror port or authorized capture point is needed.
- This is a lab project starter, not a hardened production service. Do not expose it publicly without authentication, stricter upload controls, and deployment hardening.
- IPv6 extension headers, advanced fragmentation reassembly, PCAPNG metadata edge cases, and full IEEE 802.3 LLC/SNAP decoding are not comprehensively implemented in this starter.

## GitHub

From the parent folder:
```bash
git init
git add .
git commit -m "Add Network Traffic Framing Analyzer backend"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
git push -u origin main
```

If your repository already has a remote or commits, check `git status` and `git remote -v` before adding a remote or pushing.
