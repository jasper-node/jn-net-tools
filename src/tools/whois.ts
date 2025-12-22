// Reusable TextEncoder/TextDecoder instances to avoid repeated instantiation
const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();

export interface WhoisResult {
  data?: string;
  error?: string;
}

export async function whois(domain: string, server = "whois.iana.org"): Promise<WhoisResult> {
  try {
    const conn = await Deno.connect({ hostname: server, port: 43 });
    await conn.write(ENCODER.encode(domain + "\r\n"));

    const buf = new Uint8Array(4096);
    const chunks: Uint8Array[] = [];
    let n: number | null;

    while ((n = await conn.read(buf)) !== null && n > 0) {
      // Store a copy of the data to avoid buffer reuse issues
      chunks.push(buf.subarray(0, n));
    }

    conn.close();

    // Decode all chunks at once for better performance
    const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const combined = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of chunks) {
      combined.set(chunk, offset);
      offset += chunk.length;
    }

    return {
      data: DECODER.decode(combined),
    };
  } catch (e) {
    return {
      error: e instanceof Error ? e.message : String(e),
    };
  }
}
