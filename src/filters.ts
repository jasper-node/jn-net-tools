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
      example: 'tools.sniff("en0", "tcp", 5000, 10)',
    },
    {
      pattern: "udp",
      description: "Capture only UDP packets",
      example: 'tools.sniff("en0", "udp", 5000, 10)',
    },
    {
      pattern: "arp",
      description: "Capture only ARP packets",
      example: 'tools.sniff("en0", "arp", 5000, 10)',
    },
    {
      pattern: "icmp",
      description: "Capture only ICMP packets",
      example: 'tools.sniff("en0", "icmp", 5000, 10)',
    },
    {
      pattern: "ipv6",
      description: "Capture only IPv6 packets",
      example: 'tools.sniff("en0", "ipv6", 5000, 10)',
    },
    {
      pattern: "tcp port <port>",
      description: "Capture TCP packets on a specific port",
      example: 'tools.sniff("en0", "tcp port 443", 5000, 10)',
    },
    {
      pattern: "udp port <port>",
      description: "Capture UDP packets on a specific port",
      example: 'tools.sniff("en0", "udp port 53", 5000, 10)',
    },
    {
      pattern: "port <port>",
      description: "Capture packets on a specific port (any protocol)",
      example: 'tools.sniff("en0", "port 80", 5000, 10)',
    },
    {
      pattern: "host <ip>",
      description: "Capture packets to/from a specific IP address",
      example: 'tools.sniff("en0", "host 1.1.1.1", 5000, 10)',
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

/**
 * Validate a filter pattern
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
      return ["tcp", "udp", "arp", "icmp", "ipv6", "ip6"].includes(protocol);
    }
  }

  // Port filters
  if (parts.length === 3 && parts[1] === "port") {
    const protocol = parts[0];
    const port = parts[2];
    if (protocol && port && (protocol === "tcp" || protocol === "udp")) {
      return !isNaN(parseInt(port));
    }
  }

  // Generic port filter
  if (parts.length === 2 && parts[0] === "port") {
    const port = parts[1];
    if (port) {
      return !isNaN(parseInt(port));
    }
  }

  // Host filter
  if (parts.length === 2 && parts[0] === "host") {
    const host = parts[1];
    return host !== undefined && host.length > 0;
  }

  return false;
}
