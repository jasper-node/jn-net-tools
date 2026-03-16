# JasperNode Net Tools

A high-performance network diagnostic library for Deno, powering the JasperNode AI Agent. It combines a **Rust** system layer (for raw socket operations) with **Deno** native tools to provide a complete IT troubleshooting suite.

Applicable to IPv4 only.

## Features

This library uses a **hybrid architecture**:

- **Rust (FFI)**: Handles low-level, high-performance, or raw socket tasks.
- **Deno (Native)**: Handles high-level protocols and text-based diagnostics.

| Category         | Tool                   | Implementation | Description                                                                   |
| ---------------- | ---------------------- | -------------- | ----------------------------------------------------------------------------- |
| **Connectivity** | `Ping`                 | 🦀 Rust        | ICMP Echo requests with detailed per-packet stats.                            |
|                  | `TraceRoute`           | 🦀 Rust        | Layer 3 path analysis (Windows: native ICMP API).                             |
|                  | `MTR`                  | 🦀 Rust        | Continuous traceroute with jitter/loss statistics (Windows: native ICMP API). |
| **Performance**  | `Bandwidth`            | 🦀 Rust        | TCP/UDP throughput testing.                                                   |
| **Discovery**    | `ArpScan`              | 🦀 Rust        | Layer 2 local device discovery.                                               |
|                  | `LldpDiscover`         | 🦀 Rust        | Passive LLDP neighbor discovery (switch/port identification).                 |
|                  | `LldpSend`             | 🦀 Rust        | Send LLDP advertisement frame from the host.                                  |
|                  | `DcpIdentify`          | 🦀 Rust        | PROFINET DCP device discovery (find PLCs/IO modules).                         |
|                  | `DcpGet`               | 🦀 Rust        | Read PROFINET device parameters (IP, name, role) by MAC address.              |
|                  | `GetInterfaces`        | 🦀 Rust        | List adapters, IPs, MAC addresses, gateways, and DNS servers.                 |
|                  | `GetNetworkInterfaces` | 🦀+🦕 Hybrid   | Enhanced interface list with IPv4/IPv6 separation and gateway/DNS info.       |
|                  | `GetDefaultInterface`  | 🦀+🦕 Hybrid   | Identifies the network interface used for internet access.                    |
| **Diagnostics**  | `Sniff`                | 🦀 Rust        | Live packet capture (uses `AF_PACKET` on Linux, `Npcap` on Windows).          |
|                  | `CheckPort`            | 🦀 Rust        | TCP/UDP port availability check.                                              |
| **Application**  | `DNS`                  | 🦀 Rust        | Deep DNS resolution and record inspection.                                    |
|                  | `HTTP`                 | 🦕 Deno        | Web diagnostics (Latency, SSL status, Headers).                               |
|                  | `Whois`                | 🦕 Deno        | Domain ownership registration info.                                           |

## Installation

```bash
deno add jsr:@controlx-io/jn-net-tools
```

## Prerequisites

- **Deno**: v2.6+ (Requires `--allow-ffi --unstable-ffi`)
- **Rust**: v1.91+ (Only if building from source)
- **Linux**: `libpcap-dev` is required for compilation. `setcap` may be required for raw socket tools (Ping/TraceRoute/MTR) without root.
- **macOS**: Root privileges required for raw socket tools (Ping/TraceRoute/MTR).
- **Windows**: [Npcap](https://npcap.com/) must be installed (ensure "Install Npcap in WinPcap API-compatible Mode" is checked). ICMP tools (Ping/TraceRoute/MTR) work without Administrator privileges via native Windows API.

## Build & Install

### Option 1: Download Pre-built Binaries

Download the latest pre-compiled binaries from GitHub Releases:

```bash
# Add to make sure you have the latest version
deno add jsr:@controlx-io/jn-net-tools
deno run --allow-net --allow-read --allow-write --allow-run jsr:@controlx-io/jn-net-tools/download_lib
```

This will automatically download and extract the appropriate binaries for your platform.

### Option 2: Build from Source

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
console.log(await net.lldpDiscover("eth0", 10000)); // Listen for LLDP neighbors for 10s
console.log(await net.dcpIdentify("eth0", 5000)); // Find PROFINET devices

const interfaces = await net.getNetworkInterfaces(); // Enhanced interface list with gateways/DNS
console.log(interfaces);
const defaultInterface = await net.getDefaultInterface(); // Interface used for internet access
console.log(defaultInterface);

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

# LLDP: listen for switch/router neighbors (default 30s, pass interface and timeout as args)
deno run -A examples/lldp_example.ts [interface] [timeout_seconds]

# PROFINET DCP: discover industrial devices and read their parameters
deno run -A examples/dcp_example.ts [interface]

# Requires elevated privileges (Linux: sudo or setcap | macOS: sudo | Windows: regular user)
deno run -A examples/ping_example.ts
deno run -A examples/mtr_example.ts
deno run -A examples/traceroute_example.ts
```

## 📡 Network Interface Discovery

The library provides three methods for discovering network interfaces:

### `getInterfaces()` - Basic Interface List

Returns a simple list of network interfaces with IP addresses and MAC addresses:

```typescript
const interfaces = await net.getInterfaces();
// Returns: Array of interfaces with name, mac, ips, subnet_masks, is_up
```

### `getNetworkInterfaces()` - Enhanced Interface List

Returns a comprehensive interface list that combines Deno's native interface data with Rust-extracted gateway and DNS information:

```typescript
const interfaces = await net.getNetworkInterfaces();
```

**Features:**

- **IPv4/IPv6 Separation**: IPs are split into `ips` (IPv4) and `ip6s` (IPv6) arrays
- **Gateway Information**: Shows IPv4 gateways for each interface
- **DNS Servers**: Lists IPv4 DNS servers configured for each interface
- **Virtual Interface Filtering**: Automatically filters out virtual/filter adapters (WFP, QoS, Npcap filters, etc.)
- **Grouped by System Name**: Interfaces are grouped by their system name (e.g., Npcap device name on Windows)

**Example Output:**

```json
[
  {
    "name": "Wi-Fi",
    "mac": "14:85:7f:41:ed:d5",
    "ips": ["192.168.97.107"],
    "ip6s": ["fe80::614b:a4d7:eb32:2669"],
    "subnet_masks": ["ffff:ffff:ffff:ffff::", "255.255.255.0"],
    "is_up": true,
    "systemName": "\\Device\\NPF_{C95FBE07-8A6F-41BC-B89C-7E6441862B4A}",
    "gateways": ["192.168.97.1"],
    "dnsServers": ["192.168.97.1"],
    "description": "Intel(R) Wi-Fi 6 AX201 160MHz"
  }
]
```

**Platform Support:**

- **Windows**: Uses `GetAdaptersAddresses` API to extract gateway and DNS information
- **Linux**: Reads `/proc/net/route` for gateways and `/etc/resolv.conf` for DNS
- **macOS**: Uses `netstat -rn` for gateways and `/etc/resolv.conf` for DNS

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
import { getSupportedFilters } from "@controlx-io/jn-net-tools";

const filters = getSupportedFilters();
// Returns all supported filter patterns with descriptions
```

| Filter Pattern    | Description          | Example                                  |
| ----------------- | -------------------- | ---------------------------------------- |
| `tcp`             | TCP packets only     | `sniff("en0", "tcp", 5000, 10)`          |
| `udp`             | UDP packets only     | `sniff("en0", "udp", 5000, 10)`          |
| `arp`             | ARP packets only     | `sniff("en0", "arp", 5000, 10)`          |
| `icmp`            | ICMP packets only    | `sniff("en0", "icmp", 5000, 10)`         |
| `ipv6`            | IPv6 packets only    | `sniff("en0", "ipv6", 5000, 10)`         |
| `lldp`            | LLDP packets only    | `sniff("en0", "lldp", 30000, 10)`        |
| `dcp`             | PROFINET DCP only    | `sniff("en0", "dcp", 5000, 10)`          |
| `tcp port <port>` | TCP on specific port | `sniff("en0", "tcp port 443", 5000, 10)` |
| `udp port <port>` | UDP on specific port | `sniff("en0", "udp port 53", 5000, 10)`  |
| `port <port>`     | Any protocol on port | `sniff("en0", "port 80", 5000, 10)`      |
| `host <ip>`       | Packets to/from IP   | `sniff("en0", "host 1.1.1.1", 5000, 10)` |

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

## Release Build

The pre-compiled FFI binaries are built and released automatically via GitHub Actions.

### Triggering a Release

1. **Tag-based trigger:**
   Push a version tag to the repository with version from src_jnnt/Cargo.toml
   ```bash
   VERSION=v0.1.5 && git tag $VERSION && git push origin $VERSION
   ```
   This triggers the `Build and Bundle Binaries` workflow, which builds all binaries and creates a new GitHub Release.

2. **Manual trigger:**
   - Go to the **Actions** tab in the GitHub repository.
   - Select the **Build and Bundle Binaries** workflow.
   - Click **Run workflow**.
   - (Optional) Provide a version tag (e.g., `v1.0.0`).

3. **JSR Publish:**
   ```bash
   deno publish
   ```

## License

MIT
