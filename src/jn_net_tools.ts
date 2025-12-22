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
  subnet_masks: string[];
  is_up: boolean;
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
