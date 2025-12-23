# JNNetTools API Reference for LLMs

This document describes each API method in `JNNetTools` and when an LLM should call it.

## Initialization & Setup

### `init(libPath?: string)`

Initializes the JNNetTools library. Must be called before using any other methods.

- **When to use**: Always call this first when starting a network operation session.

### `checkPrerequisites()`

Verifies that required system prerequisites are installed (e.g., Npcap on Windows).

- **When to use**: When troubleshooting initialization errors or verifying system setup before network operations.

### `close()`

Closes the library and releases resources.

- **When to use**: When finished with all network operations to clean up resources.

## Connectivity Testing

### `ping(target: string, count = 4, timeoutMs = 5000)`

Sends ICMP ping packets to test host reachability and measure latency.

- **When to use**: To check if a host is online, measure network latency, or diagnose basic connectivity issues.

### `traceRoute(target: string, maxHops = 30, timeoutMs = 2000)`

Traces the network path to a target, showing each hop and its latency.

- **When to use**: To identify network routing issues, find where packets are being dropped, or understand the network path to a destination.

### `mtr(target: string, durationMs = 5000)`

Combines ping and traceroute, continuously measuring latency and packet loss to each hop.

- **When to use**: For continuous monitoring of network path quality, identifying intermittent issues, or analyzing jitter and packet loss over time.

## Network Interface Management

### `getInterfaces()`

Returns a list of all network interfaces on the system.

- **When to use**: To discover available network interfaces before performing interface-specific operations (e.g., ARP scan, packet sniffing).

### `getDefaultInterface()`

Identifies the network interface used for default internet connectivity.

- **When to use**: When you need to know which interface is actively used for internet access, or to automatically select an interface for network operations.

### `getNetworkInterfaces()`

Returns detailed information about all network interfaces including IPs, MAC addresses, gateways, DNS servers, and status.

- **When to use**: For comprehensive network configuration analysis, troubleshooting network setup, or when you need gateway/DNS information.

## Local Network Discovery

### `arpScan(iface: string, timeoutMs = 5000)`

Scans the local network segment using ARP to discover devices and their MAC addresses.

- **When to use**: To discover devices on a local network, map IP addresses to MAC addresses, or identify active hosts on a subnet.

## Packet Analysis

### `sniff(iface: string, filter: string | null, durationMs = 5000, maxPackets = 100, includeData = false)`

Captures and analyzes network packets on a specified interface.

- **When to use**: For network traffic analysis, debugging network protocols, monitoring network activity, or investigating security issues. Use `filter` to capture specific traffic (e.g., "tcp port 80").

## Port & Service Testing

### `checkPort(target: string, port: number, proto = "tcp", timeoutMs = 5000)`

Tests if a specific port is open and accepting connections on a target host.

- **When to use**: To verify if a service is running on a port, check firewall rules, or diagnose connection issues to specific services.

### `bandwidth(target: string, port: number, proto = "tcp", durationMs = 10000)`

Measures network throughput between the local machine and a target.

- **When to use**: To test network speed, measure available bandwidth, or benchmark network performance between two endpoints.

## DNS & Domain Services

### `dns(domain: string, server: string | null, recordType: string | null)`

Performs DNS lookups to resolve domain names or query specific DNS record types.

- **When to use**: To resolve domain names to IP addresses, query DNS records (A, AAAA, MX, etc.), or test DNS server functionality.

### `whois(domain: string, server?: string)`

Retrieves WHOIS information for a domain name.

- **When to use**: To get domain registration information, contact details, or domain ownership data.

## Web Testing

### `checkWeb(url: string)`

Tests HTTP/HTTPS connectivity to a web URL and retrieves response information.

- **When to use**: To verify if a website is accessible, check HTTP response codes, or test web service availability.
