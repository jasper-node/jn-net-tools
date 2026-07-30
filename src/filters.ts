/**
 * Supported packet filter patterns for the sniff function.
 * These filters are applied in userspace and work across all platforms.
 */

export interface FilterPattern {
  pattern: string;
  description: string;
  example?: string;
}

/**
 * Get all supported filter patterns
 */
export function getSupportedFilters(): FilterPattern[] {
  return [
    {
      pattern: "tcp",
      description: "Capture only TCP packets",
      example: 'tools.sniff("eth0", "tcp", 5000, 10)',
    },
    {
      pattern: "udp",
      description: "Capture only UDP packets",
      example: 'tools.sniff("eth0", "udp", 5000, 10)',
    },
    {
      pattern: "arp",
      description: "Capture only ARP packets",
      example: 'tools.sniff("eth0", "arp", 5000, 10)',
    },
    {
      pattern: "icmp",
      description: "Capture only ICMP packets",
      example: 'tools.sniff("eth0", "icmp", 5000, 10)',
    },
    {
      pattern: "ipv6",
      description: "Capture only IPv6 packets",
      example: 'tools.sniff("eth0", "ipv6", 5000, 10)',
    },
    {
      pattern: "lldp",
      description: "Capture only LLDP packets",
      example: 'tools.sniff("eth0", "lldp", 30000, 10)',
    },
    {
      pattern: "dcp",
      description: "Capture only PROFINET DCP packets",
      example: 'tools.sniff("eth0", "dcp", 5000, 10)',
    },
    {
      pattern: "tcp port <port>",
      description: "Capture TCP packets on a specific port",
      example: 'tools.sniff("eth0", "tcp port 443", 5000, 10)',
    },
    {
      pattern: "udp port <port>",
      description: "Capture UDP packets on a specific port",
      example: 'tools.sniff("eth0", "udp port 53", 5000, 10)',
    },
    {
      pattern: "port <port>",
      description: "Capture packets on a specific port (any protocol)",
      example: 'tools.sniff("eth0", "port 80", 5000, 10)',
    },
    {
      pattern: "host <ip>",
      description: "Capture packets to/from a specific IP address",
      example: 'tools.sniff("eth0", "host 1.1.1.1", 5000, 10)',
    },
  ];
}

/**
 * Get filter patterns grouped by category
 */
export function getFiltersByCategory() {
  return {
    protocols: [
      { pattern: "tcp", description: "TCP packets only" },
      { pattern: "udp", description: "UDP packets only" },
      { pattern: "arp", description: "ARP packets only" },
      { pattern: "icmp", description: "ICMP packets only" },
      { pattern: "ipv6", description: "IPv6 packets only" },
      { pattern: "lldp", description: "LLDP packets only" },
      { pattern: "dcp", description: "PROFINET DCP packets only" },
    ],
    ports: [
      { pattern: "tcp port <port>", description: "TCP on specific port" },
      { pattern: "udp port <port>", description: "UDP on specific port" },
      { pattern: "port <port>", description: "Any protocol on specific port" },
    ],
    hosts: [
      { pattern: "host <ip>", description: "Packets to/from specific IP" },
    ],
  };
}

function isPort(token: string): boolean {
  return /^\d{1,5}$/.test(token) && Number(token) <= 65535;
}

/**
 * A literal the capture can compare against. Packet source and destination are
 * IPs for IPv4/IPv6 frames and MAC addresses for LLDP, DCP and other
 * ethertypes; names are never resolved, so a hostname matches nothing.
 *
 * Deliberately no stricter than the capture: it may pass through a malformed
 * colon-form that `parse_filter` then refuses with a reason, but it never
 * rejects an address the capture would have accepted.
 */
function isLiteralAddress(token: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(token)) {
    return token.split(".").every((octet) => Number(octet) <= 255);
  }
  return token.includes(":") && /^[0-9a-f:.]+$/.test(token);
}

/**
 * Validate a filter pattern. Mirrors `parse_filter` in
 * `src_jnnt/src/sniff/capture.rs` — the capture refuses anything this rejects,
 * so the two grammars have to change together.
 */
export function isValidFilter(filter: string): boolean {
  if (!filter || filter.trim() === "") {
    return true; // Empty filter is valid (captures all)
  }

  const parts = filter.toLowerCase().trim().split(/\s+/);

  // Protocol-only filters
  if (parts.length === 1) {
    const protocol = parts[0];
    if (protocol) {
      return ["tcp", "udp", "arp", "icmp", "ipv6", "ip6", "lldp", "dcp"].includes(protocol);
    }
  }

  // Port filters
  if (parts.length === 3 && parts[1] === "port") {
    const protocol = parts[0];
    const port = parts[2];
    if (protocol && port && (protocol === "tcp" || protocol === "udp")) {
      return isPort(port);
    }
  }

  // Generic port filter
  if (parts.length === 2 && parts[0] === "port") {
    const port = parts[1];
    return port !== undefined && isPort(port);
  }

  // Host filter
  if (parts.length === 2 && parts[0] === "host") {
    const host = parts[1];
    return host !== undefined && isLiteralAddress(host);
  }

  return false;
}
