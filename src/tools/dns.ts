export interface DNSResult {
  status: string;
  time_ms?: number;
  records?: string[];
  error?: string;
}

export async function diagnoseDNS(hostname: string, _server?: string): Promise<DNSResult> {
  const start = performance.now();
  try {
    const records = await Deno.resolveDns(hostname, "A");
    return {
      status: "OK",
      time_ms: performance.now() - start,
      records: records.map((r) => r.toString()),
    };
  } catch (e) {
    return {
      status: "Error",
      error: e instanceof Error ? e.message : String(e),
    };
  }
}
