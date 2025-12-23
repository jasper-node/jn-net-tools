import { assertEquals, assertExists } from "@std/assert";
import { stub } from "@std/testing/mock";
import { checkWeb } from "../tools/http.ts";

Deno.test({
  name: "checkWeb - successful HTTP request",
  fn: async () => {
    const mockHeaders = new Headers({
      "content-type": "text/html",
      "server": "nginx",
    });

    const mockResponse = {
      status: 200,
      headers: mockHeaders,
    } as Response;

    const fetchStub = stub(globalThis, "fetch", () => Promise.resolve(mockResponse));

    try {
      const result = await checkWeb("http://example.com");

      assertEquals(result.status, 200);
      assertExists(result.latency_ms);
      assertEquals(typeof result.latency_ms, "number");
      assertEquals(result.latency_ms >= 0, true);
      assertEquals(result.ssl_ok, "N/A");
      assertExists(result.headers);
      assertEquals(result.headers["content-type"], "text/html");
      assertEquals(result.headers["server"], "nginx");
      assertEquals(result.error, undefined);
    } finally {
      fetchStub.restore();
    }
  },
});

Deno.test({
  name: "checkWeb - successful HTTPS request",
  fn: async () => {
    const mockHeaders = new Headers({
      "content-type": "application/json",
    });

    const mockResponse = {
      status: 200,
      headers: mockHeaders,
    } as Response;

    const fetchStub = stub(globalThis, "fetch", () => Promise.resolve(mockResponse));

    try {
      const result = await checkWeb("https://example.com");

      assertEquals(result.status, 200);
      assertExists(result.latency_ms);
      assertEquals(typeof result.latency_ms, "number");
      assertEquals(result.ssl_ok, true);
      assertExists(result.headers);
      assertEquals(result.error, undefined);
    } finally {
      fetchStub.restore();
    }
  },
});

Deno.test({
  name: "checkWeb - HTTP 404 status",
  fn: async () => {
    const mockHeaders = new Headers({
      "content-type": "text/html",
    });

    const mockResponse = {
      status: 404,
      headers: mockHeaders,
    } as Response;

    const fetchStub = stub(globalThis, "fetch", () => Promise.resolve(mockResponse));

    try {
      const result = await checkWeb("http://example.com/notfound");

      assertEquals(result.status, 404);
      assertExists(result.latency_ms);
      assertEquals(result.ssl_ok, "N/A");
      assertEquals(result.error, undefined);
    } finally {
      fetchStub.restore();
    }
  },
});

Deno.test({
  name: "checkWeb - HTTP 500 status",
  fn: async () => {
    const mockHeaders = new Headers();

    const mockResponse = {
      status: 500,
      headers: mockHeaders,
    } as Response;

    const fetchStub = stub(globalThis, "fetch", () => Promise.resolve(mockResponse));

    try {
      const result = await checkWeb("http://example.com");

      assertEquals(result.status, 500);
      assertExists(result.latency_ms);
      assertEquals(result.error, undefined);
    } finally {
      fetchStub.restore();
    }
  },
});

Deno.test({
  name: "checkWeb - network error",
  fn: async () => {
    const fetchStub = stub(
      globalThis,
      "fetch",
      () => Promise.reject(new Error("Network error")),
    );

    try {
      const result = await checkWeb("http://example.com");

      assertEquals(result.status, undefined);
      assertEquals(result.latency_ms, undefined);
      assertEquals(result.headers, undefined);
      assertEquals(result.ssl_ok, undefined);
      assertExists(result.error);
      assertEquals(result.error, "Network error");
    } finally {
      fetchStub.restore();
    }
  },
});

Deno.test({
  name: "checkWeb - DNS resolution error",
  fn: async () => {
    const fetchStub = stub(
      globalThis,
      "fetch",
      () => Promise.reject(new Error("DNS resolution failed")),
    );

    try {
      const result = await checkWeb("http://invalid.invalid");

      assertEquals(result.status, undefined);
      assertExists(result.error);
      assertEquals(result.error, "DNS resolution failed");
    } finally {
      fetchStub.restore();
    }
  },
});

Deno.test({
  name: "checkWeb - connection timeout error",
  fn: async () => {
    const fetchStub = stub(
      globalThis,
      "fetch",
      () => Promise.reject(new Error("Connection timeout")),
    );

    try {
      const result = await checkWeb("http://example.com");

      assertExists(result.error);
      assertEquals(result.error, "Connection timeout");
    } finally {
      fetchStub.restore();
    }
  },
});

Deno.test({
  name: "checkWeb - empty headers",
  fn: async () => {
    const mockHeaders = new Headers();

    const mockResponse = {
      status: 200,
      headers: mockHeaders,
    } as Response;

    const fetchStub = stub(globalThis, "fetch", () => Promise.resolve(mockResponse));

    try {
      const result = await checkWeb("http://example.com");

      assertEquals(result.status, 200);
      assertExists(result.headers);
      assertEquals(Object.keys(result.headers).length, 0);
    } finally {
      fetchStub.restore();
    }
  },
});

Deno.test({
  name: "checkWeb - multiple headers",
  fn: async () => {
    const mockHeaders = new Headers({
      "content-type": "text/html; charset=utf-8",
      "server": "Apache",
      "x-custom-header": "custom-value",
      "cache-control": "no-cache",
    });

    const mockResponse = {
      status: 200,
      headers: mockHeaders,
    } as Response;

    const fetchStub = stub(globalThis, "fetch", () => Promise.resolve(mockResponse));

    try {
      const result = await checkWeb("https://example.com");

      assertEquals(result.status, 200);
      assertExists(result.headers);
      assertEquals(result.headers["content-type"], "text/html; charset=utf-8");
      assertEquals(result.headers["server"], "Apache");
      assertEquals(result.headers["x-custom-header"], "custom-value");
      assertEquals(result.headers["cache-control"], "no-cache");
    } finally {
      fetchStub.restore();
    }
  },
});

Deno.test({
  name: "checkWeb - latency is measured",
  fn: async () => {
    const mockHeaders = new Headers();

    const mockResponse = {
      status: 200,
      headers: mockHeaders,
    } as Response;

    const fetchStub = stub(
      globalThis,
      "fetch",
      () =>
        new Promise((resolve) => {
          setTimeout(() => resolve(mockResponse), 50);
        }),
    );

    try {
      const result = await checkWeb("http://example.com");

      assertEquals(result.status, 200);
      assertExists(result.latency_ms);
      assertEquals(result.latency_ms >= 50, true);
      assertEquals(result.latency_ms < 200, true);
    } finally {
      fetchStub.restore();
    }
  },
});

Deno.test({
  name: "checkWeb - non-Error thrown",
  fn: async () => {
    const fetchStub = stub(
      globalThis,
      "fetch",
      () => Promise.reject("String error"),
    );

    try {
      const result = await checkWeb("http://example.com");

      assertExists(result.error);
      assertEquals(result.error, "String error");
    } finally {
      fetchStub.restore();
    }
  },
});

