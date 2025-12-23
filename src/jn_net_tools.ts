import {
  callFFIString,
  callFFIStringNullable,
  encodeCString,
  type LoadedFFILibrary,
  loadFFILibrary,
} from "./ffi.ts";
import * as httpTools from "./tools/http.ts";
import * as whoisTools from "./tools/whois.ts";

export interface PingPacketResult {
  seq: number;
  status: string;
  rtt_ms?: number;
}

export interface PingResult {
  target: string;
  alive: boolean;
  loss_percent: number;
  avg_rtt_ms: number;
  packets: PingPacketResult[];
  error?: string;
}

export interface TraceRouteResult {
  target: string;
  hops: Array<{
    hop: number;
    probes: Array<{
      ip: string;
      hostname?: string;
      latency_ms: number;
    }>;
  }>;
  error?: string;
}

export interface MtrResult {
  target: string;
  hops: Array<{
    hop: number;
    ip: string;
    sent: number;
    received: number;
    loss_percent: number;
    avg_latency_ms: number;
    min_latency_ms: number;
    max_latency_ms: number;
    jitter_ms: number;
  }>;
  error?: string;
}

export interface InterfaceInfo {
  name: string;
  mac: string;
  ips: string[];
  ip6s: string[];
  subnet_masks: string[];
  is_up: boolean;
  systemName?: string;
  gateways?: string[];
  dnsServers?: string[];
  description?: string;
}

export interface ArpDevice {
  ip: string;
  mac: string;
}

export interface ArpScanResult {
  interface: string;
  devices: ArpDevice[];
  error?: string;
}

export interface PacketSummary {
  ts: string;
  src: string;
  dst: string;
  proto: string;
  info: string;
  data?: string;
}

export interface SniffResult {
  captured: number;
  packets: PacketSummary[];
  error?: string;
}

export interface PortCheckResult {
  port: number;
  open: boolean;
  error?: string;
}

export interface BandwidthResult {
  target: string;
  port: number;
  protocol: string;
  bytes_sent: number;
  bytes_received: number;
  duration_ms: number;
  throughput_mbps: number;
  error?: string;
}

export interface DNSResult {
  status: string;
  time_ms?: number;
  records?: string[];
  error?: string;
}

export class JNNetTools {
  private lib: LoadedFFILibrary | null = null;
  private initialized = false;
  private initError: Error | null = null;

  async init(libPath?: string): Promise<void> {
    if (this.initialized) {
      return;
    }
    try {
      this.lib = await loadFFILibrary(libPath);
      this.initialized = true;
      this.initError = null;
    } catch (e) {
      this.initError = e instanceof Error ? e : new Error(String(e));
      throw this.initError;
    }
  }

  private ensureInitialized(): void {
    if (this.initError) {
      const isWindows = Deno.build.os === "windows";
      const msg = isWindows
        ? `JNNetTools failed to initialize. Npcap is likely missing. Please install Npcap with "WinPcap API-compatible mode" enabled. Original error: ${this.initError.message}`
        : `JNNetTools failed to initialize: ${this.initError.message}`;
      throw new Error(msg);
    }
    if (!this.initialized || this.lib === null) {
      throw new Error("JNNetTools not initialized. Call init() first.");
    }
  }

  async checkPrerequisites(): Promise<{ status: string; error?: string }> {
    this.ensureInitialized();
    const resultPtr = await this.lib!.symbols.net_check_prerequisites();
    if (resultPtr === null) {
      return { status: "Error", error: "Failed to check prerequisites" };
    }
    const view = new Deno.UnsafePointerView(resultPtr);
    const result = view.getCString();
    await this.lib!.symbols.free_string(resultPtr);
    const parsed = JSON.parse(result) as { status: string; error?: string };
    if (parsed.status === "Error" && parsed.error) {
      throw new Error(parsed.error);
    }
    return parsed;
  }

  async ping(target: string, count = 4, timeoutMs = 5000): Promise<PingResult> {
    this.ensureInitialized();
    const result = await callFFIString(
      this.lib!.symbols,
      this.lib!.symbols.net_ping,
      target,
      count,
      timeoutMs,
    );
    return JSON.parse(result) as PingResult;
  }

  async traceRoute(target: string, maxHops = 30, timeoutMs = 2000): Promise<TraceRouteResult> {
    this.ensureInitialized();
    const result = await callFFIString(
      this.lib!.symbols,
      this.lib!.symbols.net_trace_route,
      target,
      maxHops,
      timeoutMs,
    );
    return JSON.parse(result) as TraceRouteResult;
  }

  async mtr(target: string, durationMs = 5000): Promise<MtrResult> {
    this.ensureInitialized();
    const result = await callFFIString(
      this.lib!.symbols,
      this.lib!.symbols.net_mtr,
      target,
      durationMs,
    );
    return JSON.parse(result) as MtrResult;
  }

  async getInterfaces(): Promise<InterfaceInfo[]> {
    this.ensureInitialized();
    const resultPtr = await this.lib!.symbols.net_get_interfaces();
    if (resultPtr === null) {
      return [];
    }
    const view = new Deno.UnsafePointerView(resultPtr);
    const result = view.getCString();
    await this.lib!.symbols.free_string(resultPtr);
    return JSON.parse(result) as InterfaceInfo[];
  }

  async getDefaultInterface(): Promise<InterfaceInfo | null> {
    this.ensureInitialized();

    // Get the local IP used for internet access
    const resultPtr = await this.lib!.symbols.net_get_default_local_ip();
    if (resultPtr === null) {
      return null;
    }
    const view = new Deno.UnsafePointerView(resultPtr);
    const result = view.getCString();
    await this.lib!.symbols.free_string(resultPtr);

    const parsed = JSON.parse(result) as { local_ip: string; error?: string };
    if (parsed.error || !parsed.local_ip) {
      return null;
    }

    // Get all network interfaces
    const interfaces = await this.getNetworkInterfaces();

    // Find the interface that has this IP
    const defaultInterface = interfaces.find((iface) => iface.ips.includes(parsed.local_ip));

    return defaultInterface || null;
  }

  async getNetworkInterfaces(): Promise<InterfaceInfo[]> {
    this.ensureInitialized();

    // Helper to check if an IP is IPv4
    const isIPv4 = (ip: string): boolean => {
      return ip.includes(".") && !ip.includes(":");
    };

    // Helper to check if interface is virtual/filter (should be filtered out)
    const isVirtualInterface = (name: string, description?: string): boolean => {
      const nameLower = name.toLowerCase();
      const descLower = (description || "").toLowerCase();
      return (
        nameLower.includes("-wfp") ||
        nameLower.includes("-qos") ||
        nameLower.includes("-filter") ||
        nameLower.includes("-npcap") ||
        nameLower.includes("-virtualbox") ||
        nameLower.includes("-twincat") ||
        nameLower.includes("-native wifi") ||
        nameLower.includes("-virtual wifi") ||
        descLower.includes("filter") ||
        descLower.includes("wfp") ||
        descLower.includes("qos") ||
        descLower.includes("miniport") ||
        descLower.includes("tunneling") ||
        descLower.includes("6to4") ||
        descLower.includes("teredo") ||
        descLower.includes("ip-https") ||
        // Filter out specific redundant interfaces
        descLower.includes("wi-fi direct") ||
        descLower.includes("kernel debug")
      );
    };

    // Get Deno network interfaces
    const denoInterfaces = Deno.networkInterfaces();
    if (!denoInterfaces) {
      return [];
    }

    // Get Rust interface details (gateways, DNS, system names, is_up)
    const resultPtr = await this.lib!.symbols.net_get_interface_details();
    if (resultPtr === null) {
      // Fallback to Deno interfaces only
      const interfaceMap = new Map<string, InterfaceInfo>();
      for (const iface of denoInterfaces) {
        if (isVirtualInterface(iface.name)) continue;
        const existing = interfaceMap.get(iface.name) || {
          name: iface.name,
          mac: iface.mac || "",
          ips: [],
          ip6s: [],
          subnet_masks: [],
          is_up: false,
        };
        if (isIPv4(iface.address)) {
          existing.ips.push(iface.address);
        } else {
          existing.ip6s.push(iface.address);
        }
        existing.subnet_masks.push(iface.netmask || "");
        interfaceMap.set(iface.name, existing);
      }
      return Array.from(interfaceMap.values());
    }

    const view = new Deno.UnsafePointerView(resultPtr);
    const result = view.getCString();
    await this.lib!.symbols.free_string(resultPtr);
    const rustDetails = JSON.parse(result) as Array<{
      name: string;
      system_name: string;
      gateways: string[];
      dns_servers: string[];
      is_up: boolean;
      description?: string;
    }>;

    // Filter out virtual interfaces from Rust details
    const filteredRustDetails = rustDetails.filter(
      (detail) => !isVirtualInterface(detail.name, detail.description),
    );

    // Create a map of Rust details by system_name (to group by)
    const detailsMapBySystem = new Map<string, typeof rustDetails[0]>();
    for (const detail of filteredRustDetails) {
      // Use the first non-virtual detail for each system_name
      if (!detailsMapBySystem.has(detail.system_name)) {
        detailsMapBySystem.set(detail.system_name, detail);
      }
    }

    // Group Deno interfaces by systemName (from Rust details)
    const interfaceMapBySystem = new Map<string, InterfaceInfo>();

    for (const iface of denoInterfaces) {
      // Find matching Rust detail by name
      const rustDetail = filteredRustDetails.find((d) => d.name === iface.name);
      if (!rustDetail && isVirtualInterface(iface.name)) continue;

      const systemName = rustDetail?.system_name || iface.name;

      // Skip if this systemName is already processed and it's a virtual interface
      if (isVirtualInterface(iface.name, rustDetail?.description)) continue;

      const existing = interfaceMapBySystem.get(systemName);
      if (existing) {
        if (isIPv4(iface.address)) {
          if (!existing.ips.includes(iface.address)) {
            existing.ips.push(iface.address);
          }
        } else {
          if (!existing.ip6s.includes(iface.address)) {
            existing.ip6s.push(iface.address);
          }
        }
        if (iface.netmask && !existing.subnet_masks.includes(iface.netmask)) {
          existing.subnet_masks.push(iface.netmask);
        }
      } else {
        // Filter gateways and DNS to IPv4 only
        const ipv4Gateways = (rustDetail?.gateways || []).filter(isIPv4);
        const ipv4DnsServers = (rustDetail?.dns_servers || []).filter(isIPv4);

        interfaceMapBySystem.set(systemName, {
          name: rustDetail?.name || iface.name,
          mac: iface.mac || "",
          ips: isIPv4(iface.address) ? [iface.address] : [],
          ip6s: isIPv4(iface.address) ? [] : [iface.address],
          subnet_masks: iface.netmask ? [iface.netmask] : [],
          is_up: rustDetail?.is_up ?? false,
          systemName: systemName,
          gateways: ipv4Gateways.length > 0 ? ipv4Gateways : undefined,
          dnsServers: ipv4DnsServers.length > 0 ? ipv4DnsServers : undefined,
          description: rustDetail?.description,
        });
      }
    }

    // Add any Rust details that don't have Deno interfaces (but filter virtual)
    for (const detail of filteredRustDetails) {
      if (!interfaceMapBySystem.has(detail.system_name)) {
        const ipv4Gateways = detail.gateways.filter(isIPv4);
        const ipv4DnsServers = detail.dns_servers.filter(isIPv4);

        interfaceMapBySystem.set(detail.system_name, {
          name: detail.name,
          mac: "",
          ips: [],
          ip6s: [],
          subnet_masks: [],
          is_up: detail.is_up,
          systemName: detail.system_name,
          gateways: ipv4Gateways.length > 0 ? ipv4Gateways : undefined,
          dnsServers: ipv4DnsServers.length > 0 ? ipv4DnsServers : undefined,
          description: detail.description,
        });
      }
    }

    return Array.from(interfaceMapBySystem.values());
  }

  async arpScan(iface: string, timeoutMs = 5000): Promise<ArpScanResult> {
    this.ensureInitialized();
    const result = await callFFIString(
      this.lib!.symbols,
      this.lib!.symbols.net_arp_scan,
      iface,
      timeoutMs,
    );
    const parsed = JSON.parse(result) as ArpScanResult;
    if (Deno.build.os === "windows" && parsed.error && parsed.error.includes("not found")) {
      parsed.error +=
        " (Ensure Npcap is installed in WinPcap-compatible mode and the interface exists)";
    }
    return parsed;
  }

  async sniff(
    iface: string,
    filter: string | null = null,
    durationMs = 5000,
    maxPackets = 100,
    includeData = false,
  ): Promise<SniffResult> {
    this.ensureInitialized();
    // net_sniff signature: (iface, filter, duration_ms, max_packets, include_data)
    const ifaceCstr = encodeCString(iface);
    const ifacePtr = Deno.UnsafePointer.of(ifaceCstr as BufferSource);
    if (ifacePtr === null) {
      throw new Error("Failed to create interface C string");
    }

    let filterPtr: Deno.PointerValue | null = null;
    if (filter !== null) {
      const filterCstr = encodeCString(filter);
      filterPtr = Deno.UnsafePointer.of(filterCstr as BufferSource);
    }

    const resultPtr = await (this.lib!.symbols.net_sniff as (
      iface: Deno.PointerValue,
      filter: Deno.PointerValue,
      duration_ms: number,
      max_packets: number,
      include_data: number,
    ) => Promise<Deno.PointerValue>)(
      ifacePtr,
      filterPtr,
      durationMs,
      maxPackets,
      includeData ? 1 : 0,
    );
    if (resultPtr === null) {
      return { captured: 0, packets: [], error: "Failed to sniff" };
    }
    const view = new Deno.UnsafePointerView(resultPtr);
    const result = view.getCString();
    await this.lib!.symbols.free_string(resultPtr);
    const parsed = JSON.parse(result) as SniffResult;

    if (
      Deno.build.os === "windows" && parsed.error && parsed.error.includes("not found")
    ) {
      parsed.error +=
        " (Ensure Npcap is installed in WinPcap-compatible mode and the interface exists)";
    }
    return parsed;
  }

  async checkPort(
    target: string,
    port: number,
    proto = "tcp",
    timeoutMs = 5000,
  ): Promise<PortCheckResult> {
    this.ensureInitialized();
    const targetCstr = encodeCString(target);
    const targetPtr = Deno.UnsafePointer.of(targetCstr as BufferSource);
    if (targetPtr === null) {
      throw new Error("Failed to create target C string");
    }

    const protoCstr = encodeCString(proto);
    const protoPtr = Deno.UnsafePointer.of(protoCstr as BufferSource);
    if (protoPtr === null) {
      throw new Error("Failed to create proto C string");
    }

    const resultPtr = await this.lib!.symbols.net_check_port(
      targetPtr,
      port,
      protoPtr,
      timeoutMs,
    );
    if (resultPtr === null) {
      return { port, open: false, error: "Failed to check port" };
    }
    const view = new Deno.UnsafePointerView(resultPtr);
    const result = view.getCString();
    await this.lib!.symbols.free_string(resultPtr);
    return JSON.parse(result) as PortCheckResult;
  }

  async bandwidth(
    target: string,
    port: number,
    proto = "tcp",
    durationMs = 10000,
  ): Promise<BandwidthResult> {
    this.ensureInitialized();
    const targetCstr = encodeCString(target);
    const targetPtr = Deno.UnsafePointer.of(targetCstr as BufferSource);
    if (targetPtr === null) {
      throw new Error("Failed to create target C string");
    }

    const protoCstr = encodeCString(proto);
    const protoPtr = Deno.UnsafePointer.of(protoCstr as BufferSource);
    if (protoPtr === null) {
      throw new Error("Failed to create proto C string");
    }

    const resultPtr = await this.lib!.symbols.net_bandwidth_test(
      targetPtr,
      port,
      protoPtr,
      durationMs,
    );
    if (resultPtr === null) {
      return {
        target,
        port,
        protocol: proto,
        bytes_sent: 0,
        bytes_received: 0,
        duration_ms: 0,
        throughput_mbps: 0,
        error: "Failed to run bandwidth test",
      };
    }
    const view = new Deno.UnsafePointerView(resultPtr);
    const result = view.getCString();
    await this.lib!.symbols.free_string(resultPtr);
    return JSON.parse(result) as BandwidthResult;
  }

  async dns(
    domain: string,
    server: string | null = null,
    recordType: string | null = null,
  ): Promise<DNSResult> {
    this.ensureInitialized();
    const result = await callFFIStringNullable(
      this.lib!.symbols,
      this.lib!.symbols.net_dns_lookup,
      domain,
      server,
      recordType,
    );
    return JSON.parse(result) as DNSResult;
  }

  // Deno-native tools
  async checkWeb(url: string): Promise<ReturnType<typeof httpTools.checkWeb>> {
    return await httpTools.checkWeb(url);
  }

  async whois(domain: string, server?: string): Promise<ReturnType<typeof whoisTools.whois>> {
    return await whoisTools.whois(domain, server);
  }

  close(): void {
    if (this.lib) {
      this.lib.close();
      this.lib = null;
    }
    this.initialized = false;
  }
}
