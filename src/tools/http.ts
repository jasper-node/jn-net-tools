export interface HTTPResult {
  status?: number;
  latency_ms?: number;
  headers?: Record<string, string>;
  ssl_ok?: boolean | string;
  error?: string;
}

export async function checkWeb(url: string): Promise<HTTPResult> {
  const start = performance.now();
  try {
    const res = await fetch(url);
    const time = performance.now() - start;
    const headers: Record<string, string> = {};
    res.headers.forEach((value, key) => {
      headers[key] = value;
    });

    return {
      status: res.status,
      latency_ms: time,
      headers,
      ssl_ok: url.startsWith("https") ? true : "N/A",
    };
  } catch (e) {
    return {
      error: e instanceof Error ? e.message : String(e),
    };
  }
}
