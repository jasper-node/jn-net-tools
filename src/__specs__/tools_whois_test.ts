import { assertEquals, assertExists } from "@std/assert";
import { stub } from "@std/testing/mock";
import { whois } from "../tools/whois.ts";

// Helper to create a mock Deno.Conn for testing
function createMockConn(responseData: string): Deno.Conn {
  const encoder = new TextEncoder();
  const responseBytes = encoder.encode(responseData);
  let readCalled = false;

  return {
    read: (buf: Uint8Array) => {
      if (!readCalled) {
        readCalled = true;
        const bytesToCopy = Math.min(buf.length, responseBytes.length);
        buf.set(responseBytes.subarray(0, bytesToCopy));
        return Promise.resolve(bytesToCopy);
      }
      return Promise.resolve(null);
    },
    write: (_data: Uint8Array) => {
      return Promise.resolve(_data.length);
    },
    close: () => {},
  } as Deno.Conn;
}

Deno.test({
  name: "whois - successful query with default server",
  fn: async () => {
    const mockResponse = "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar\n";
    const mockConn = createMockConn(mockResponse);

    const connectStub = stub(
      Deno,
      "connect",
      () => Promise.resolve(mockConn as any),
    );

    try {
      const result = await whois("example.com");

      assertExists(result.data);
      assertEquals(result.data, mockResponse);
      assertEquals(result.error, undefined);
    } finally {
      connectStub.restore();
    }
  },
});

Deno.test({
  name: "whois - successful query with custom server",
  fn: async () => {
    const mockResponse = "Domain: example.org\nStatus: Active\n";
    const mockConn = createMockConn(mockResponse);

    const connectStub = stub(
      Deno,
      "connect",
      () => Promise.resolve(mockConn as any),
    );

    try {
      const result = await whois("example.org", "whois.pir.org");

      assertExists(result.data);
      assertEquals(result.data, mockResponse);
      assertEquals(result.error, undefined);
    } finally {
      connectStub.restore();
    }
  },
});

Deno.test({
  name: "whois - empty response",
  fn: async () => {
    const mockConn = createMockConn("");

    const connectStub = stub(
      Deno,
      "connect",
      () => Promise.resolve(mockConn as any),
    );

    try {
      const result = await whois("example.com");

      assertExists(result.data);
      assertEquals(result.data, "");
      assertEquals(result.error, undefined);
    } finally {
      connectStub.restore();
    }
  },
});

Deno.test({
  name: "whois - large response with multiple chunks",
  fn: async () => {
    // Create a response larger than typical buffer
    const mockResponse = "Domain Name: EXAMPLE.COM\n".repeat(500);
    const encoder = new TextEncoder();
    const responseBytes = encoder.encode(mockResponse);
    let offset = 0;

    const mockConn = {
      read: (buf: Uint8Array) => {
        if (offset >= responseBytes.length) {
          return Promise.resolve(null);
        }
        const chunkSize = Math.min(buf.length, responseBytes.length - offset);
        // Copy data into the buffer
        const chunk = responseBytes.subarray(offset, offset + chunkSize);
        buf.set(chunk, 0);
        offset += chunkSize;
        return Promise.resolve(chunkSize);
      },
      write: (_data: Uint8Array) => Promise.resolve(_data.length),
      close: () => {},
    } as Deno.Conn;

    const connectStub = stub(
      Deno,
      "connect",
      () => Promise.resolve(mockConn as any),
    );

    try {
      const result = await whois("example.com");

      assertExists(result.data);
      assertEquals(result.data, mockResponse);
      assertEquals(result.error, undefined);
    } finally {
      connectStub.restore();
    }
  },
});

Deno.test({
  name: "whois - connection error",
  fn: async () => {
    const connectStub = stub(
      Deno,
      "connect",
      () => Promise.reject(new Error("Connection refused")),
    );

    try {
      const result = await whois("example.com");

      assertEquals(result.data, undefined);
      assertExists(result.error);
      assertEquals(result.error, "Connection refused");
    } finally {
      connectStub.restore();
    }
  },
});

Deno.test({
  name: "whois - network timeout error",
  fn: async () => {
    const connectStub = stub(
      Deno,
      "connect",
      () => Promise.reject(new Error("Network timeout")),
    );

    try {
      const result = await whois("example.com", "whois.iana.org");

      assertEquals(result.data, undefined);
      assertExists(result.error);
      assertEquals(result.error, "Network timeout");
    } finally {
      connectStub.restore();
    }
  },
});

Deno.test({
  name: "whois - DNS resolution error for server",
  fn: async () => {
    const connectStub = stub(
      Deno,
      "connect",
      () => Promise.reject(new Error("DNS resolution failed")),
    );

    try {
      const result = await whois("example.com", "invalid.server.invalid");

      assertEquals(result.data, undefined);
      assertExists(result.error);
      assertEquals(result.error, "DNS resolution failed");
    } finally {
      connectStub.restore();
    }
  },
});

Deno.test({
  name: "whois - read error during response",
  fn: async () => {
    const mockConn = {
      read: (_buf: Uint8Array) => Promise.reject(new Error("Read error")),
      write: (_data: Uint8Array) => Promise.resolve(_data.length),
      close: () => {},
    } as Deno.Conn;

    const connectStub = stub(
      Deno,
      "connect",
      () => Promise.resolve(mockConn as any),
    );

    try {
      const result = await whois("example.com");

      assertEquals(result.data, undefined);
      assertExists(result.error);
      assertEquals(result.error, "Read error");
    } finally {
      connectStub.restore();
    }
  },
});

Deno.test({
  name: "whois - write error when sending query",
  fn: async () => {
    const mockConn = {
      read: (_buf: Uint8Array) => Promise.resolve(null),
      write: (_data: Uint8Array) => Promise.reject(new Error("Write error")),
      close: () => {},
    } as Deno.Conn;

    const connectStub = stub(
      Deno,
      "connect",
      () => Promise.resolve(mockConn as any),
    );

    try {
      const result = await whois("example.com");

      assertEquals(result.data, undefined);
      assertExists(result.error);
      assertEquals(result.error, "Write error");
    } finally {
      connectStub.restore();
    }
  },
});

Deno.test({
  name: "whois - non-Error thrown",
  fn: async () => {
    const connectStub = stub(
      Deno,
      "connect",
      () => Promise.reject("String error"),
    );

    try {
      const result = await whois("example.com");

      assertEquals(result.data, undefined);
      assertExists(result.error);
      assertEquals(result.error, "String error");
    } finally {
      connectStub.restore();
    }
  },
});

Deno.test({
  name: "whois - response with special characters",
  fn: async () => {
    const mockResponse = "Domain: example.com\nRegistrar: Test™\nContact: info@example.com\n";
    const mockConn = createMockConn(mockResponse);

    const connectStub = stub(
      Deno,
      "connect",
      () => Promise.resolve(mockConn as any),
    );

    try {
      const result = await whois("example.com");

      assertExists(result.data);
      assertEquals(result.data, mockResponse);
      assertEquals(result.error, undefined);
    } finally {
      connectStub.restore();
    }
  },
});

Deno.test({
  name: "whois - response with UTF-8 characters",
  fn: async () => {
    const mockResponse = "Domain: 例え.jp\nRegistrar: 日本レジストラ\n";
    const mockConn = createMockConn(mockResponse);

    const connectStub = stub(
      Deno,
      "connect",
      () => Promise.resolve(mockConn as any),
    );

    try {
      const result = await whois("例え.jp", "whois.jprs.jp");

      assertExists(result.data);
      assertEquals(result.data, mockResponse);
      assertEquals(result.error, undefined);
    } finally {
      connectStub.restore();
    }
  },
});
