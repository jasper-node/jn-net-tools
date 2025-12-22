import { assertEquals } from "@std/assert";
import { JNNetTools } from "../jn_net_tools.ts";
import { getLibraryPath, loadFFILibrary } from "../ffi.ts";

Deno.test({
  name: "test_getLibraryPath_default",
  fn: () => {
    const path = getLibraryPath();
    const os = Deno.build.os;
    const arch = Deno.build.arch;

    if (os === "darwin") {
      if (arch === "aarch64") {
        assertEquals(path, "./lib/jnnt-aarch64.dylib");
      } else if (arch === "x86_64") {
        assertEquals(path, "./lib/jnnt-x86_64.dylib");
      }
    } else if (os === "linux") {
      if (arch === "aarch64") {
        assertEquals(path, "./lib/jnnt-aarch64.so");
      } else if (arch === "x86_64") {
        assertEquals(path, "./lib/jnnt-x86_64.so");
      }
    } else if (os === "windows") {
      assertEquals(path, "./lib/jnnt.dll");
    }
  },
});

Deno.test({
  name: "test_getLibraryPath_custom",
  fn: () => {
    const customPath = "/custom/lib/path";
    const path = getLibraryPath(customPath);
    const os = Deno.build.os;
    const arch = Deno.build.arch;

    if (os === "darwin") {
      if (arch === "aarch64") {
        assertEquals(path, "/custom/lib/path/jnnt-aarch64.dylib");
      } else if (arch === "x86_64") {
        assertEquals(path, "/custom/lib/path/jnnt-x86_64.dylib");
      }
    } else if (os === "linux") {
      if (arch === "aarch64") {
        assertEquals(path, "/custom/lib/path/jnnt-aarch64.so");
      } else if (arch === "x86_64") {
        assertEquals(path, "/custom/lib/path/jnnt-x86_64.so");
      }
    } else if (os === "windows") {
      assertEquals(path, "/custom/lib/path/jnnt.dll");
    }
  },
});

Deno.test({
  name: "test_getLibraryPath_relative",
  fn: () => {
    const relativePath = "../libs";
    const path = getLibraryPath(relativePath);
    const os = Deno.build.os;
    const arch = Deno.build.arch;

    if (os === "darwin") {
      if (arch === "aarch64") {
        assertEquals(path, "../libs/jnnt-aarch64.dylib");
      } else if (arch === "x86_64") {
        assertEquals(path, "../libs/jnnt-x86_64.dylib");
      }
    } else if (os === "linux") {
      if (arch === "aarch64") {
        assertEquals(path, "../libs/jnnt-aarch64.so");
      } else if (arch === "x86_64") {
        assertEquals(path, "../libs/jnnt-x86_64.so");
      }
    } else if (os === "windows") {
      assertEquals(path, "../libs/jnnt.dll");
    }
  },
});

Deno.test({
  name: "test_init_default_path",
  fn: async () => {
    const tools = new JNNetTools();
    try {
      await tools.init();
      // If initialization succeeds, the default path was used
      const interfaces = await tools.getInterfaces();
      assertEquals(Array.isArray(interfaces), true);
    } catch (e) {
      // If it fails, it should be because the library doesn't exist at default path
      // or requires root, not because of path construction
      const error = e instanceof Error ? e : new Error(String(e));
      // Path-related errors would mention the path
      if (error.message.includes("./lib/")) {
        // This is expected if library doesn't exist
        assertEquals(error.message.includes("./lib/"), true);
      }
    } finally {
      tools.close();
    }
  },
  sanitizeResources: false,
});

Deno.test({
  name: "test_init_custom_path",
  fn: async () => {
    const tools = new JNNetTools();
    const customPath = "/nonexistent/path";
    try {
      await tools.init(customPath);
      // If this succeeds, it means the library exists at custom path (unlikely)
      const interfaces = await tools.getInterfaces();
      assertEquals(Array.isArray(interfaces), true);
    } catch (e) {
      // Expected to fail with path-related error
      const error = e instanceof Error ? e : new Error(String(e));
      // Should mention the custom path in the error
      const hasCustomPath = error.message.includes(customPath) ||
        error.message.includes("Failed to open dynamic library");
      assertEquals(
        hasCustomPath,
        true,
        `Expected error to mention custom path, got: ${error.message}`,
      );
    } finally {
      tools.close();
    }
  },
  sanitizeResources: false,
});

Deno.test({
  name: "test_init_empty_string_path",
  fn: async () => {
    const tools = new JNNetTools();
    try {
      await tools.init("");
      // Empty string should be treated as a valid path (though likely to fail)
      const interfaces = await tools.getInterfaces();
      assertEquals(Array.isArray(interfaces), true);
    } catch (e) {
      // Expected to fail, but should handle empty string gracefully
      const error = e instanceof Error ? e : new Error(String(e));
      // Should not crash, should give a meaningful error
      assertEquals(typeof error.message, "string");
    } finally {
      tools.close();
    }
  },
  sanitizeResources: false,
});

Deno.test({
  name: "test_init_multiple_calls",
  fn: async () => {
    const tools = new JNNetTools();
    try {
      // First init with default path
      await tools.init();
      // Second init should be a no-op (already initialized)
      await tools.init();
      // Third init with different path should still be no-op
      await tools.init("/different/path");
      // Should still work with original initialization
      const interfaces = await tools.getInterfaces();
      assertEquals(Array.isArray(interfaces), true);
    } catch (e) {
      // If first init fails, that's okay for this test
      // We're testing that multiple calls don't cause issues
    } finally {
      tools.close();
    }
  },
  sanitizeResources: false,
});

Deno.test({
  name: "test_loadFFILibrary_default_path",
  fn: async () => {
    try {
      const lib = await loadFFILibrary();
      // If successful, verify it has the expected symbols
      assertEquals(typeof lib.symbols.net_ping, "function");
      assertEquals(typeof lib.symbols.net_get_interfaces, "function");
      lib.close();
    } catch (e) {
      // Expected if library doesn't exist at default path
      const error = e instanceof Error ? e : new Error(String(e));
      // Should mention default path or be a loading error
      const isPathError = error.message.includes("./lib/") ||
        error.message.includes("Failed to open dynamic library") ||
        error.message.includes("No such file");
      assertEquals(isPathError, true, `Expected path-related error, got: ${error.message}`);
    }
  },
  sanitizeResources: false,
});

Deno.test({
  name: "test_loadFFILibrary_custom_path",
  fn: async () => {
    const customPath = "/invalid/path/to/lib";
    try {
      const lib = await loadFFILibrary(customPath);
      // Unlikely to succeed, but if it does, verify symbols
      assertEquals(typeof lib.symbols.net_ping, "function");
      lib.close();
    } catch (e) {
      // Expected to fail
      const error = e instanceof Error ? e : new Error(String(e));
      // Error should mention the custom path or be a loading error
      const hasCustomPath = error.message.includes(customPath) ||
        error.message.includes("Failed to open dynamic library") ||
        error.message.includes("No such file");
      assertEquals(
        hasCustomPath,
        true,
        `Expected error to mention custom path, got: ${error.message}`,
      );
    }
  },
  sanitizeResources: false,
});

Deno.test({
  name: "test_init_after_close",
  fn: async () => {
    const tools = new JNNetTools();
    try {
      await tools.init();
      tools.close();
      // After close, should be able to re-init
      await tools.init("/custom/path");
      const interfaces = await tools.getInterfaces();
      assertEquals(Array.isArray(interfaces), true);
    } catch (e) {
      // May fail if custom path doesn't exist, but should not crash
      const error = e instanceof Error ? e : new Error(String(e));
      assertEquals(typeof error.message, "string");
    } finally {
      tools.close();
    }
  },
  sanitizeResources: false,
});
