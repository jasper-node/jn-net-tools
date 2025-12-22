export interface WhoisResult {
  data?: string;
  error?: string;
}

export async function whois(domain: string, server = "whois.iana.org"): Promise<WhoisResult> {
  try {
    const conn = await Deno.connect({ hostname: server, port: 43 });
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    await conn.write(encoder.encode(domain + "\r\n"));

    const buf = new Uint8Array(4096);
    let result = "";
    let n: number | null;

    while ((n = await conn.read(buf)) !== null && n > 0) {
      result += decoder.decode(buf.subarray(0, n));
    }

    conn.close();

    return {
      data: result,
    };
  } catch (e) {
    return {
      error: e instanceof Error ? e.message : String(e),
    };
  }
}
