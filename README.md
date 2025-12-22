# JasperNode Net Tools

A high-performance network diagnostic library for Deno, powering the JasperNode AI Agent. It combines a **Rust** system layer (for raw socket operations) with **Deno** native tools to provide a complete IT troubleshooting suite.

Applicable to IPv4 only.

## Features

This library uses a **hybrid architecture**:

- **Rust (FFI)**: Handles low-level, high-performance, or raw socket tasks.
- **Deno (Native)**: Handles high-level protocols and text-based diagnostics.

| Category         | Tool            | Implementation | Description                                                          |
| ---------------- | --------------- | -------------- | -------------------------------------------------------------------- |
| **Connectivity** | `Ping`          | 🦀 Rust        | ICMP Echo requests with detailed per-packet stats.                   |
|                  | `TraceRoute`    | 🦀 Rust        | Layer 3 path analysis.                                               |
|                  | `MTR`           | 🦀 Rust        | Continuous traceroute with jitter/loss statistics.                   |
| **Performance**  | `Bandwidth`     | 🦀 Rust        | TCP/UDP throughput testing.                                          |
| **Discovery**    | `ArpScan`       | 🦀 Rust        | Layer 2 local device discovery.                                      |
|                  | `GetInterfaces` | 🦀 Rust        | List adapters, IPs, and MAC addresses.                               |
| **Diagnostics**  | `Sniff`         | 🦀 Rust        | Live packet capture (uses `AF_PACKET` on Linux, `Npcap` on Windows). |
|                  | `CheckPort`     | 🦀 Rust        | TCP/UDP port availability check.                                     |
| **Application**  | `DNS`           | 🦀 Rust        | Deep DNS resolution and record inspection.                           |
|                  | `HTTP`          | 🦕 Deno        | Web diagnostics (Latency, SSL status, Headers).                      |
|                  | `Whois`         | 🦕 Deno        | Domain ownership registration info.                                  |

## Installation

```bash
deno add jsr:@controlx-io/jn-net-tools
```

## Prerequisites

- **Deno**: v2.6+ (Requires `--allow-ffi --unstable-ffi`)
- **Rust**: v1.91+ (Only if building from source)
- **Linux**: `setcap` may be required for raw socket tools (Ping/MTR) without root.
- **Windows**: [Npcap](https://npcap.com/) must be installed (ensure "Install Npcap in WinPcap API-compatible Mode" is checked).

## Build & Install

1. **Clone the repository:**

```bash
git clone https://github.com/jasper-node/jn-net-tools.git
cd jn-net-tools
```

2. **Build the Rust shared library:**

```bash
deno task build
```

_This generates `jnnt-aarch64.so` (Linux), `.dylib` (macOS), or `.dll` (Windows) in `lib/`

## Usage

Import the main class in your Deno project. It automatically routes calls to the appropriate backend (Rust or Deno).

```typescript
import { JNNetTools } from "@controlx-io/jn-net-tools";

const net = new JNNetTools();
await net.init();

// 1. Connectivity (Rust FFI)
console.log(await net.ping("8.8.8.8"));
console.log(await net.mtr("1.1.1.1", 5000)); // Run MTR for 5 seconds

// 2. Discovery (Rust FFI)
console.log(await net.arpScan("eth0"));

// 3. Performance (Rust FFI)
// Test TCP throughput to target on port 8080 for 10 seconds
console.log(await net.bandwidth("192.168.1.50", 8080, "tcp", 10000));

// 4. Application Diagnostics
// DNS Lookup using Google DNS
console.log(await net.dns("google.com", "8.8.8.8", "A"));
console.log(await net.checkWeb("https://example.com"));

// Cleanup FFI resources
net.close();
```

## Running Tests

Includes Rust and Deno tests.

```bash
deno task test
```

## Running Examples

```bash
deno run -A examples/arp_scan_example.ts
deno run -A examples/whois_example.ts
deno run -A examples/bandwidth_example.ts
deno run -A examples/check_port_example.ts
deno run -A examples/dns_example.ts
deno run -A examples/get_interfaces_example.ts
deno run -A examples/http_example.ts
deno run -A examples/sniff_example.ts
deno run -A examples/filters_example.ts  # View supported packet filter patterns

# requires sudo
sudo deno run -A examples/ping_example.ts
sudo deno run -A examples/mtr_example.ts
sudo deno run -A examples/traceroute_example.ts
```

## 🦈 Packet Sniffing Configuration

The `Sniff` feature performs live packet capture using raw sockets. Because this interacts directly with the network driver, it requires elevated privileges or specific drivers depending on your OS.

### Windows

- **Requirement:** You must install [Npcap](https://npcap.com/).
- **Installation:** During installation, ensure you check **"Install Npcap in WinPcap API-compatible Mode"**.
- **Permissions:** Generally requires running the script as Administrator, unless you configure Npcap to allow non-admin access (the "Restrict Npcap driver's access to Administrators only" option must be unchecked during install).

### Linux

- **Requirement:** The application needs `CAP_NET_RAW` capabilities to open `AF_PACKET` sockets.
- **Option 1 (Recommended):** Grant capabilities to the Deno binary:
  ```bash
  setcap cap_net_raw,cap_net_admin=eip $(which deno)
  ```
- **Option 2:** Run your script with `sudo`:
  ```bash
  deno run --allow-ffi --unstable-ffi your_script.ts
  ```

### macOS

- **Requirement:** Access to `/dev/bpf*` (Berkeley Packet Filter).
- **Permissions:** macOS typically requires root privileges for packet capture.
  ```bash
  deno run --allow-ffi --unstable-ffi your_script.ts
  ```
- **Troubleshooting:** If you receive "Operation not permitted" even with sudo, ensure your terminal application has "Full Disk Access" or "Input Monitoring" permissions in System Settings > Privacy & Security.

### Packet Filtering

The `sniff()` function supports packet filtering to capture only specific traffic. Filters are applied in userspace and work across all platforms.

#### Basic Usage

```typescript
// Capture only TCP traffic on port 443 (HTTPS)
const result = await net.sniff("en0", "tcp port 443", 5000, 10);

// Capture only ARP packets
const arpResult = await net.sniff("eth0", "arp", 5000, 10);
```

#### Supported Filter Patterns

```typescript
import { getSupportedFilters } from "@controlx-io/jn-net-tools/filters";

const filters = getSupportedFilters();
// Returns all supported filter patterns with descriptions
```

| Filter Pattern    | Description          | Example                                  |
| ----------------- | -------------------- | ---------------------------------------- |
| `tcp`             | TCP packets only     | `sniff("en0", "tcp", 5000, 10)`          |
| `udp`             | UDP packets only     | `sniff("en0", "udp", 5000, 10)`          |
| `arp`             | ARP packets only     | `sniff("en0", "arp", 5000, 10)`          |
| `icmp`            | ICMP packets only    | `sniff("en0", "icmp", 5000, 10)`         |
| `tcp port <port>` | TCP on specific port | `sniff("en0", "tcp port 443", 5000, 10)` |
| `udp port <port>` | UDP on specific port | `sniff("en0", "udp port 53", 5000, 10)`  |
| `port <port>`     | Any protocol on port | `sniff("en0", "port 80", 5000, 10)`      |
| `host <ip>`       | Packets to/from IP   | `sniff("en0", "host 1.1.1.1", 5000, 10)` |

#### Filter API

The library provides helper functions to work with filters:

```typescript
import {
  getFiltersByCategory, // Get filters grouped by category
  getSupportedFilters, // Get all filter patterns
  isValidFilter, // Validate a filter string
} from "@controlx-io/jn-net-tools/filters";

// Check if filter is valid before using
if (isValidFilter("tcp port 443")) {
  const result = await net.sniff("en0", "tcp port 443", 5000, 10);
}
```

#### Packet Data

Captured packets include raw packet data as hex-encoded string:

```json
{
  "captured": 10,
  "packets": [
    {
      "ts": "1766402581",
      "src": "192.168.1.100",
      "dst": "1.1.1.1",
      "proto": "TCP",
      "info": "62831 -> 443 [ACK]",
      "data": "942a6f0845bf4e41f6efb3b50800450000340000..."
    }
  ]
}
```

## License

MIT
