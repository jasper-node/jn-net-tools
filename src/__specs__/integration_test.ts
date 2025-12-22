import { assertEquals, assertExists } from "@std/assert";
import { type InterfaceInfo, JNNetTools } from "../jn_net_tools.ts";

// Note: These tests require root privileges (CAP_NET_RAW) to pass successfully.
// If run without root, they will panic or fail assertions.

let tools: JNNetTools | null = null;
let onlineInterface: InterfaceInfo | null = null;

async function ensureToolsInitialized(): Promise<JNNetTools> {
  if (!tools) {
    tools = new JNNetTools();
    await tools.init();
  }
  return tools;
}

async function findOnlineInterface(): Promise<InterfaceInfo | null> {
  const toolsInstance = await ensureToolsInitialized();
  const interfaces = await toolsInstance.getInterfaces();
  assertExists(interfaces, "Expected array of interfaces");
  assertEquals(Array.isArray(interfaces), true, "Expected array of interfaces");

  // First, verify system connectivity using DNS lookup
  let systemOnline = false;
  try {
    const dnsResult = await toolsInstance.dns("example.com");
    if (dnsResult.status === "OK" && !dnsResult.error) {
      systemOnline = true;
    }
  } catch {
    // System not online
  }

  if (!systemOnline) {
    console.log("Warning: System connectivity test failed");
  }

  // Try to find a non-loopback interface that is suitable
  for (const iface of interfaces) {
    // Skip loopback and specialized interfaces
    if (
      iface.name.includes("lo") ||
      iface.name.includes("anpi") ||
      !iface.is_up ||
      iface.ips.length === 0
    ) {
      continue;
    }

    // Return first suitable interface (system connectivity already verified)
    return iface;
  }

  // Fallback: return first interface if none found
  return interfaces[0] ?? null;
}

Deno.test({
  name: "test_get_interfaces",
  fn: async () => {
    const toolsInstance = await ensureToolsInitialized();
    const result = await toolsInstance.getInterfaces();
    assertExists(result, "Expected array of interfaces");
    assertEquals(Array.isArray(result), true, "Expected array of interfaces");
    assertEquals(result.length > 0, true, "Expected at least one interface");
  },
  sanitizeResources: false,
});

Deno.test({
  name: "test_check_prerequisites",
  fn: async () => {
    const toolsInstance = await ensureToolsInitialized();
    const result = await toolsInstance.checkPrerequisites();
    assertEquals(typeof result.status, "string");
    // Status should be either "OK" or "Error"
    assertEquals(
      result.status === "OK" || result.status === "Error",
      true,
      `Expected status to be "OK" or "Error", got: ${result.status}`,
    );
  },
  sanitizeResources: false,
});

Deno.test({
  name: "test_dns_lookup",
  fn: async () => {
    const toolsInstance = await ensureToolsInitialized();
    // Test with default server
    console.log("DNS lookup: example.com (default server)");
    const result = await toolsInstance.dns("example.com");
    assertEquals(result.status, "OK");
    assertExists(result.records);
    assertEquals(Array.isArray(result.records), true);
    assertEquals(result.records!.length > 0, true);
    console.log(
      `  Status: ${result.status}, Records: ${result.records!.length}, Time: ${result.time_ms}ms`,
    );

    // Test with Google DNS
    console.log("DNS lookup: example.com (server: 8.8.8.8, type: A)");
    const result2 = await toolsInstance.dns("example.com", "8.8.8.8", "A");
    assertEquals(result2.status, "OK");
    console.log(
      `  Status: ${result2.status}, Records: ${
        result2.records?.length || 0
      }, Time: ${result2.time_ms}ms`,
    );
  },
  sanitizeResources: false,
});

Deno.test({
  name: "test_find_online_interface",
  fn: async () => {
    onlineInterface = await findOnlineInterface();
    if (onlineInterface) {
      console.log(`Using interface: ${onlineInterface.name}`);
    } else {
      console.log("Warning: No suitable online interface found");
    }
  },
  sanitizeResources: false,
});

Deno.test({
  name: "test_ping",
  fn: async () => {
    const toolsInstance = await ensureToolsInitialized();
    const target = "8.8.8.8";
    console.log(`Ping: ${target} (1 packet, 1000ms timeout)`);
    const result = await toolsInstance.ping(target, 1, 1000);

    // Fail if root privileges are required
    if (result.error && result.error.includes("root privileges")) {
      throw new Error(`Ping failed: ${result.error}`);
    }

    if (result.error) {
      throw new Error(`Ping failed: ${result.error}`);
    }

    assertEquals(typeof result.target, "string");
    assertEquals(Array.isArray(result.packets), true);
    assertEquals(result.alive, true, "Expected target to be alive");
    assertEquals(result.packets.length > 0, true, "Expected at least one packet");
    console.log(
      `  Target: ${result.target}, Alive: ${result.alive}, Loss: ${result.loss_percent}%, Avg RTT: ${result.avg_rtt_ms}ms`,
    );
  },
  sanitizeResources: false,
});

Deno.test({
  name: "test_trace_route",
  fn: async () => {
    const toolsInstance = await ensureToolsInitialized();
    const target = "8.8.8.8";
    console.log(`Trace route: ${target} (max 30 hops, 3000ms timeout)`);
    const result = await toolsInstance.traceRoute(target, 30, 3000);

    // Fail if root privileges are required
    if (result.error && result.error.includes("root privileges")) {
      throw new Error(`Trace Route failed: ${result.error}`);
    }

    if (result.error) {
      throw new Error(`Trace Route failed: ${result.error}`);
    }

    assertEquals(typeof result.target, "string");
    assertEquals(Array.isArray(result.hops), true);
    assertEquals(result.hops.length > 1, true, "Expected more than 1 hop");
    console.log(`  Target: ${result.target}, Hops: ${result.hops.length}`);
  },
  sanitizeResources: false,
});

Deno.test({
  name: "test_mtr",
  fn: async () => {
    const toolsInstance = await ensureToolsInitialized();
    const target = "8.8.8.8";
    console.log(`MTR: ${target} (1000ms duration)`);
    const result = await toolsInstance.mtr(target, 1000);
    // console.log("MTR Result:", JSON.stringify(result));

    // Fail if root privileges are required
    if (result.error && result.error.includes("root privileges")) {
      throw new Error(`MTR failed: ${result.error} (root privileges required)`);
    }

    // On some systems MTR might return 0 hops if no root without an explicit error
    if (result.hops.length === 0 && !result.error) {
      throw new Error("MTR failed: returned 0 hops (likely requires root privileges)");
    }

    if (result.error) {
      throw new Error(`MTR failed: ${result.error}`);
    }

    assertEquals(typeof result.target, "string");
    assertEquals(Array.isArray(result.hops), true);
    assertEquals(result.hops.length > 1, true, "Expected more than 1 hop");
    console.log(`  Target: ${result.target}, Hops: ${result.hops.length}`);
    const firstHop = result.hops[0];
    if (firstHop) {
      console.log(
        `  First hop: ${firstHop.ip}, Loss: ${firstHop.loss_percent}%, Avg Latency: ${firstHop.avg_latency_ms}ms`,
      );
    }
  },
  sanitizeResources: false,
});

Deno.test({
  name: "test_check_port",
  fn: async () => {
    const toolsInstance = await ensureToolsInitialized();
    // Try example.com:80 first
    const host1 = "example.com";
    const port1 = 80;
    console.log(`Check port: ${host1}:${port1} (tcp, 2000ms timeout)`);
    let result = await toolsInstance.checkPort(host1, port1, "tcp", 2000);

    if (result.open === true) {
      assertEquals(result.port, 80);
      console.log(`  Port ${result.port}: OPEN`);
    } else {
      // Fallback to 8.8.8.8:53 (which should be open)
      const host2 = "8.8.8.8";
      const port2 = 53;
      console.log(`  Port ${port1}: CLOSED, trying ${host2}:${port2}`);
      result = await toolsInstance.checkPort(host2, port2, "tcp", 2000);
      assertEquals(result.open, true, `Expected port ${port2} on ${host2} to be open`);
      console.log(`  Port ${result.port}: ${result.open ? "OPEN" : "CLOSED"}`);

      // Now check a port that should be closed
      const host3 = "8.8.8.8";
      const port3 = 54;
      console.log(`  Trying known CLOSED port ${host3}:${port3}`);
      const result3 = await toolsInstance.checkPort(host3, port3, "tcp", 1000);
      assertEquals(result3.open, false, `Expected port ${port3} on ${host3} to be closed`);
      console.log(`  Port ${result3.port}: ${result3.open ? "OPEN" : "CLOSED"}`);
    }
  },
  sanitizeResources: false,
});

Deno.test({
  name: "test_bandwidth",
  fn: async () => {
    const toolsInstance = await ensureToolsInitialized();
    // We test against example.com:80 just to see if it runs
    const host = "example.com";
    const port = 80;
    console.log(`Bandwidth test: ${host}:${port} (tcp, 500ms duration)`);
    const result = await toolsInstance.bandwidth(host, port, "tcp", 500);
    assertEquals(typeof result.target, "string");
    assertEquals(typeof result.throughput_mbps, "number");
    assertEquals(result.throughput_mbps > 0, true, "Expected non-zero throughput");
    console.log(
      `  Target: ${result.target}:${result.port}, Throughput: ${
        result.throughput_mbps.toFixed(2)
      } Mbps, Sent: ${result.bytes_sent} bytes, Received: ${result.bytes_received} bytes`,
    );
  },
  sanitizeResources: false,
});

Deno.test({
  name: "test_arp_scan",
  fn: async () => {
    if (!onlineInterface) {
      console.log("Skipping ARP scan: No interface found");
      return;
    }

    const toolsInstance = await ensureToolsInitialized();
    console.log(`ARP scan: interface ${onlineInterface.name} (500ms timeout)`);
    const result = await toolsInstance.arpScan(onlineInterface.name, 500);

    // Enforce success (requires root)
    if (result.error) {
      // Special handling for OS error 22 (Invalid argument) which can happen on macOS BPF
      // if the interface doesn't support sniffing or permissions are tricky despite root
      if (result.error.includes("os error 22")) {
        console.log("  Skipping: OS error 22 (interface may not support ARP scan)");
        return;
      }
      throw new Error(`ARP Scan failed: ${result.error}`);
    }

    assertEquals(Array.isArray(result.devices), true);
    console.log(`  Interface: ${result.interface}, Devices found: ${result.devices.length}`);
    assertEquals(result.devices.length > 0, true, "Expected at least 1 device found in ARP scan");
  },
  sanitizeResources: false,
});

Deno.test({
  name: "test_sniff",
  fn: async () => {
    if (!onlineInterface) {
      console.log("Skipping Sniff: No interface found");
      return;
    }

    const toolsInstance = await ensureToolsInitialized();
    // Sniff for 500ms without data
    console.log(
      `Sniff: interface ${onlineInterface.name} (500ms, max 10 packets, no filter, no data)`,
    );
    const result = await toolsInstance.sniff(onlineInterface.name, "", 500, 10, false);

    // Enforce success (requires root)
    if (result.error) {
      // Special handling for OS error 22 (Invalid argument) which can happen on macOS BPF
      // if the interface doesn't support sniffing or permissions are tricky despite root
      if (result.error.includes("os error 22")) {
        console.log("  Skipping: OS error 22 (interface may not support sniffing)");
        return;
      }
      throw new Error(`Sniff failed: ${result.error}`);
    }

    assertEquals(Array.isArray(result.packets), true);
    assertEquals(result.packets.length > 0, true, "Expected at least one packet captured");
    console.log(`  Captured: ${result.captured} packets, Packets array: ${result.packets.length}`);

    // Verify that packets don't have data field when includeData is false
    for (const packet of result.packets) {
      assertEquals(packet.data, undefined, "Expected no data field when includeData is false");
    }
  },
  sanitizeResources: false,
});

Deno.test({
  name: "test_sniff_with_data",
  fn: async () => {
    if (!onlineInterface) {
      throw new Error("Sniff with data failed: No interface found");
    }

    const toolsInstance = await ensureToolsInitialized();
    // Sniff for 500ms with data
    console.log(
      `Sniff: interface ${onlineInterface.name} (500ms, max 10 packets, no filter, with data)`,
    );
    const result = await toolsInstance.sniff(onlineInterface.name, "", 500, 10, true);

    // Enforce success (requires root)
    if (result.error) {
      throw new Error(`Sniff with data failed: ${result.error}`);
    }

    assertEquals(Array.isArray(result.packets), true);
    assertEquals(result.packets.length > 0, true, "Expected at least one packet captured");
    console.log(`  Captured: ${result.captured} packets, Packets array: ${result.packets.length}`);

    // Verify that packets have data field when includeData is true
    for (const packet of result.packets) {
      assertExists(packet.data, "Expected data field when includeData is true");
      assertEquals(typeof packet.data, "string", "Expected data to be a hex string");
      assertEquals(packet.data.length > 0, true, "Expected non-empty data");
      // Verify it's a valid hex string with spaces (e.g. "aa bb cc")
      assertEquals(
        /^[0-9a-f ]+$/i.test(packet.data),
        true,
        "Expected valid hex characters and spaces",
      );
      // Check strict format: 2 hex digits followed by optional space
      assertEquals(/^([0-9a-f]{2}( |$))+$/i.test(packet.data), true, "Expected format 'XX XX XX'");
      console.log(`    Packet ${packet.proto}: data length ${packet.data.length} chars`);
    }
  },
  sanitizeResources: false,
});

Deno.test({
  name: "test_whois",
  fn: async () => {
    const toolsInstance = await ensureToolsInitialized();
    console.log("Whois lookup: google.com");
    const result = await toolsInstance.whois("google.com");
    if (result.error) {
      throw new Error(`Whois failed: ${result.error}`);
    }
    assertExists(result.data);
    assertEquals(result.data!.length > 0, true, "Expected non-empty whois data");
    console.log(`  Data length: ${result.data!.length} chars`);
  },
  sanitizeResources: false,
});

// Cleanup: Close the dynamic library after all tests
Deno.test({
  name: "cleanup",
  fn: () => {
    if (tools) {
      tools.close();
      tools = null;
    }
  },
  sanitizeResources: false,
  sanitizeOps: false,
});
