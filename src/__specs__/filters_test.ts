import { assertEquals } from "@std/assert";
import { getFiltersByCategory, getSupportedFilters, isValidFilter } from "../filters.ts";

Deno.test({
  name: "getSupportedFilters returns expected array",
  fn: () => {
    const filters = getSupportedFilters();
    assertEquals(Array.isArray(filters), true);
    assertEquals(filters.length, 9);

    // Verify structure of each filter
    for (const filter of filters) {
      assertEquals(typeof filter.pattern, "string");
      assertEquals(typeof filter.description, "string");
      assertEquals(filter.pattern.length > 0, true);
      assertEquals(filter.description.length > 0, true);
    }

    // Verify some specific filters exist
    const patterns = filters.map((f) => f.pattern);
    assertEquals(patterns.includes("tcp"), true);
    assertEquals(patterns.includes("udp"), true);
    assertEquals(patterns.includes("icmp"), true);
  },
});

Deno.test({
  name: "getFiltersByCategory returns expected structure",
  fn: () => {
    const categorized = getFiltersByCategory();

    assertEquals(typeof categorized, "object");
    assertEquals(Array.isArray(categorized.protocols), true);
    assertEquals(Array.isArray(categorized.ports), true);
    assertEquals(Array.isArray(categorized.hosts), true);

    // Verify protocols category
    assertEquals(categorized.protocols.length, 5);
    const protocolPatterns = categorized.protocols.map((f) => f.pattern);
    assertEquals(protocolPatterns.includes("tcp"), true);
    assertEquals(protocolPatterns.includes("udp"), true);
    assertEquals(protocolPatterns.includes("arp"), true);
    assertEquals(protocolPatterns.includes("icmp"), true);
    assertEquals(protocolPatterns.includes("ipv6"), true);

    // Verify ports category
    assertEquals(categorized.ports.length, 3);
    const portPatterns = categorized.ports.map((f) => f.pattern);
    assertEquals(portPatterns.includes("tcp port <port>"), true);
    assertEquals(portPatterns.includes("udp port <port>"), true);
    assertEquals(portPatterns.includes("port <port>"), true);

    // Verify hosts category
    assertEquals(categorized.hosts.length, 1);
    assertEquals(categorized.hosts[0]?.pattern, "host <ip>");
  },
});

Deno.test({
  name: "isValidFilter - empty filter is valid",
  fn: () => {
    assertEquals(isValidFilter(""), true);
    assertEquals(isValidFilter("   "), true);
  },
});

Deno.test({
  name: "isValidFilter - protocol-only filters",
  fn: () => {
    assertEquals(isValidFilter("tcp"), true);
    assertEquals(isValidFilter("udp"), true);
    assertEquals(isValidFilter("arp"), true);
    assertEquals(isValidFilter("icmp"), true);
    assertEquals(isValidFilter("ipv6"), true);
    assertEquals(isValidFilter("ip6"), true);

    // Case insensitive
    assertEquals(isValidFilter("TCP"), true);
    assertEquals(isValidFilter("UDP"), true);

    // Invalid protocols
    assertEquals(isValidFilter("http"), false);
    assertEquals(isValidFilter("ftp"), false);
    assertEquals(isValidFilter("invalid"), false);
  },
});

Deno.test({
  name: "isValidFilter - protocol + port filters",
  fn: () => {
    assertEquals(isValidFilter("tcp port 80"), true);
    assertEquals(isValidFilter("tcp port 443"), true);
    assertEquals(isValidFilter("udp port 53"), true);
    assertEquals(isValidFilter("udp port 123"), true);

    // Case insensitive
    assertEquals(isValidFilter("TCP PORT 80"), true);
    assertEquals(isValidFilter("UDP PORT 53"), true);

    // Invalid protocol for port filter
    assertEquals(isValidFilter("icmp port 80"), false);
    assertEquals(isValidFilter("arp port 80"), false);

    // Invalid port (not a number)
    assertEquals(isValidFilter("tcp port abc"), false);
    assertEquals(isValidFilter("udp port xyz"), false);

    // Missing port number
    assertEquals(isValidFilter("tcp port"), false);
  },
});

Deno.test({
  name: "isValidFilter - generic port filters",
  fn: () => {
    assertEquals(isValidFilter("port 80"), true);
    assertEquals(isValidFilter("port 443"), true);
    assertEquals(isValidFilter("port 8080"), true);

    // Case insensitive
    assertEquals(isValidFilter("PORT 80"), true);

    // Invalid port (not a number)
    assertEquals(isValidFilter("port abc"), false);

    // Missing port number
    assertEquals(isValidFilter("port"), false);
  },
});

Deno.test({
  name: "isValidFilter - host filters",
  fn: () => {
    assertEquals(isValidFilter("host 192.168.1.1"), true);
    assertEquals(isValidFilter("host 1.1.1.1"), true);
    assertEquals(isValidFilter("host 8.8.8.8"), true);
    assertEquals(isValidFilter("host example.com"), true);

    // Case insensitive
    assertEquals(isValidFilter("HOST 192.168.1.1"), true);

    // Missing host
    assertEquals(isValidFilter("host"), false);
    assertEquals(isValidFilter("host "), false);
  },
});

Deno.test({
  name: "isValidFilter - complex invalid filters",
  fn: () => {
    assertEquals(isValidFilter("tcp udp"), false);
    assertEquals(isValidFilter("port 80 tcp"), false);
    assertEquals(isValidFilter("host 1.1.1.1 port 80"), false);
    assertEquals(isValidFilter("random string"), false);
  },
});

Deno.test({
  name: "isValidFilter - whitespace handling",
  fn: () => {
    assertEquals(isValidFilter("  tcp  "), true);
    assertEquals(isValidFilter("  tcp   port   80  "), true);
    assertEquals(isValidFilter("  port   80  "), true);
    assertEquals(isValidFilter("  host   1.1.1.1  "), true);
  },
});
