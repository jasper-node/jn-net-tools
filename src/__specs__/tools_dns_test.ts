import { assertEquals, assertExists } from "@std/assert";
import { stub } from "@std/testing/mock";
import { diagnoseDNS } from "../tools/dns.ts";

Deno.test({
  name: "diagnoseDNS - successful resolution with single record",
  fn: async () => {
    const resolveDnsStub = stub(
      Deno,
      "resolveDns",
      () => Promise.resolve(["93.184.216.34"]),
    );

    try {
      const result = await diagnoseDNS("example.com");

      assertEquals(result.status, "OK");
      assertExists(result.time_ms);
      assertEquals(typeof result.time_ms, "number");
      assertEquals(result.time_ms >= 0, true);
      assertExists(result.records);
      assertEquals(Array.isArray(result.records), true);
      assertEquals(result.records.length, 1);
      assertEquals(result.records[0], "93.184.216.34");
      assertEquals(result.error, undefined);
    } finally {
      resolveDnsStub.restore();
    }
  },
});

Deno.test({
  name: "diagnoseDNS - successful resolution with multiple records",
  fn: async () => {
    const resolveDnsStub = stub(
      Deno,
      "resolveDns",
      () => Promise.resolve(["8.8.8.8", "8.8.4.4"]),
    );

    try {
      const result = await diagnoseDNS("google.com");

      assertEquals(result.status, "OK");
      assertExists(result.time_ms);
      assertExists(result.records);
      assertEquals(result.records.length, 2);
      assertEquals(result.records[0], "8.8.8.8");
      assertEquals(result.records[1], "8.8.4.4");
      assertEquals(result.error, undefined);
    } finally {
      resolveDnsStub.restore();
    }
  },
});

Deno.test({
  name: "diagnoseDNS - successful resolution with empty records",
  fn: async () => {
    const resolveDnsStub = stub(
      Deno,
      "resolveDns",
      () => Promise.resolve([]),
    );

    try {
      const result = await diagnoseDNS("nxdomain.example");

      assertEquals(result.status, "OK");
      assertExists(result.time_ms);
      assertExists(result.records);
      assertEquals(result.records.length, 0);
      assertEquals(result.error, undefined);
    } finally {
      resolveDnsStub.restore();
    }
  },
});

Deno.test({
  name: "diagnoseDNS - DNS resolution error",
  fn: async () => {
    const resolveDnsStub = stub(
      Deno,
      "resolveDns",
      () => Promise.reject(new Error("DNS resolution failed")),
    );

    try {
      const result = await diagnoseDNS("invalid.invalid");

      assertEquals(result.status, "Error");
      assertEquals(result.time_ms, undefined);
      assertEquals(result.records, undefined);
      assertExists(result.error);
      assertEquals(result.error, "DNS resolution failed");
    } finally {
      resolveDnsStub.restore();
    }
  },
});

Deno.test({
  name: "diagnoseDNS - network timeout error",
  fn: async () => {
    const resolveDnsStub = stub(
      Deno,
      "resolveDns",
      () => Promise.reject(new Error("Network timeout")),
    );

    try {
      const result = await diagnoseDNS("example.com");

      assertEquals(result.status, "Error");
      assertExists(result.error);
      assertEquals(result.error, "Network timeout");
    } finally {
      resolveDnsStub.restore();
    }
  },
});

Deno.test({
  name: "diagnoseDNS - NXDOMAIN error",
  fn: async () => {
    const resolveDnsStub = stub(
      Deno,
      "resolveDns",
      () => Promise.reject(new Error("NXDOMAIN")),
    );

    try {
      const result = await diagnoseDNS("nonexistent.example.com");

      assertEquals(result.status, "Error");
      assertExists(result.error);
      assertEquals(result.error, "NXDOMAIN");
    } finally {
      resolveDnsStub.restore();
    }
  },
});

Deno.test({
  name: "diagnoseDNS - custom DNS server parameter (currently unused)",
  fn: async () => {
    const resolveDnsStub = stub(
      Deno,
      "resolveDns",
      () => Promise.resolve(["1.2.3.4"]),
    );

    try {
      // The current implementation doesn't use the server parameter, but we test the API
      const result = await diagnoseDNS("example.com", "8.8.8.8");

      assertEquals(result.status, "OK");
      assertExists(result.records);
      assertEquals(result.records[0], "1.2.3.4");
    } finally {
      resolveDnsStub.restore();
    }
  },
});

Deno.test({
  name: "diagnoseDNS - non-Error thrown",
  fn: async () => {
    const resolveDnsStub = stub(
      Deno,
      "resolveDns",
      () => Promise.reject("String error"),
    );

    try {
      const result = await diagnoseDNS("example.com");

      assertEquals(result.status, "Error");
      assertExists(result.error);
      assertEquals(result.error, "String error");
    } finally {
      resolveDnsStub.restore();
    }
  },
});

Deno.test({
  name: "diagnoseDNS - timing is reasonable",
  fn: async () => {
    const resolveDnsStub = stub(
      Deno,
      "resolveDns",
      () =>
        new Promise((resolve) => {
          setTimeout(() => resolve(["1.1.1.1"]), 10);
        }),
    );

    try {
      const result = await diagnoseDNS("example.com");

      assertEquals(result.status, "OK");
      assertExists(result.time_ms);
      assertEquals(result.time_ms >= 10, true);
      assertEquals(result.time_ms < 500, true);
    } finally {
      resolveDnsStub.restore();
    }
  },
});

Deno.test({
  name: "diagnoseDNS - handles IPv6 addresses",
  fn: async () => {
    const resolveDnsStub = stub(
      Deno,
      "resolveDns",
      () => Promise.resolve(["2606:2800:220:1:248:1893:25c8:1946"]),
    );

    try {
      const result = await diagnoseDNS("ipv6.example.com");

      assertEquals(result.status, "OK");
      assertExists(result.records);
      assertEquals(result.records[0], "2606:2800:220:1:248:1893:25c8:1946");
    } finally {
      resolveDnsStub.restore();
    }
  },
});
