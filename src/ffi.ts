// Reusable TextEncoder/TextDecoder instances to avoid repeated instantiation
const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();

/**
 * Encode a string as a null-terminated C string (Uint8Array).
 * @param str - String to encode
 * @returns Encoded bytes with null terminator
 */
export function encodeCString(str: string): Uint8Array {
  return ENCODER.encode(str + "\0");
}

export interface FFILibrary {
  net_ping: (
    target: Deno.PointerValue,
    count: number,
    timeout_ms: number,
  ) => Promise<Deno.PointerValue>;
  net_trace_route: (
    target: Deno.PointerValue,
    max_hops: number,
    timeout_ms: number,
  ) => Promise<Deno.PointerValue>;
  net_mtr: (target: Deno.PointerValue, duration_ms: number) => Promise<Deno.PointerValue>;
  net_get_interfaces: () => Promise<Deno.PointerValue>;
  net_get_interface_details: () => Promise<Deno.PointerValue>;
  net_arp_scan: (iface: Deno.PointerValue, timeout_ms: number) => Promise<Deno.PointerValue>;
  net_sniff: (
    iface: Deno.PointerValue,
    filter: Deno.PointerValue,
    duration_ms: number,
    max_packets: number,
    include_data: number,
  ) => Promise<Deno.PointerValue>;
  net_check_port: (
    target: Deno.PointerValue,
    port: number,
    proto: Deno.PointerValue,
    timeout_ms: number,
  ) => Promise<Deno.PointerValue>;
  net_bandwidth_test: (
    target: Deno.PointerValue,
    port: number,
    proto: Deno.PointerValue,
    duration_ms: number,
  ) => Promise<Deno.PointerValue>;
  net_dns_lookup: (
    domain: Deno.PointerValue,
    server: Deno.PointerValue | null,
    record_type: Deno.PointerValue | null,
  ) => Promise<Deno.PointerValue>;
  net_check_prerequisites: () => Promise<Deno.PointerValue>;
  free_string: (ptr: Deno.PointerValue) => Promise<void>;
}

export function getLibraryPath(basePath = "./lib"): string {
  const os = Deno.build.os;
  const arch = Deno.build.arch;

  switch (os) {
    case "darwin": {
      if (arch === "aarch64") {
        return `${basePath}/jnnt-aarch64.dylib`;
      } else if (arch === "x86_64") {
        return `${basePath}/jnnt-x86_64.dylib`;
      } else {
        throw new Error(`Unsupported macOS architecture: ${arch}`);
      }
    }
    case "linux": {
      if (arch === "aarch64") {
        return `${basePath}/jnnt-aarch64.so`;
      } else if (arch === "x86_64") {
        return `${basePath}/jnnt-x86_64.so`;
      } else {
        throw new Error(`Unsupported Linux architecture: ${arch}`);
      }
    }
    case "windows": {
      return `${basePath}/jnnt.dll`;
    }
    default:
      throw new Error(`Unsupported platform: ${os}`);
  }
}

export interface LoadedFFILibrary {
  symbols: FFILibrary;
  close: () => void;
}

export async function loadFFILibrary(basePath?: string): Promise<LoadedFFILibrary> {
  const libPath = getLibraryPath(basePath);
  const isDefaultPath = basePath === undefined || basePath === "./lib";

  // Check if library exists, download if missing (only for default path)
  try {
    await Deno.stat(libPath);
  } catch {
    // Library doesn't exist
    if (isDefaultPath) {
      // For default path, try to download it
      console.log(`Library not found at ${libPath}, downloading...`);
      const downloadCmd = new Deno.Command("deno", {
        args: [
          "run",
          "--allow-net",
          "--allow-write",
          "--allow-run",
          "--allow-read",
          "jsr:@controlx-io/jn-net-tools/download_lib",
        ],
      });
      const { success, stderr } = await downloadCmd.output();
      if (!success) {
        throw new Error(
          `Failed to download library: ${DECODER.decode(stderr)}`,
        );
      }
      console.log("✅ Library downloaded successfully");
      // Verify library exists after download
      try {
        await Deno.stat(libPath);
      } catch {
        throw new Error(
          `Failed to open dynamic library: Library not found at ${libPath} after download.`,
        );
      }
    } else {
      // For custom paths, don't download - just fail with a clear error
      throw new Error(
        `Failed to open dynamic library: Library not found at ${libPath}. Please ensure the library exists at the specified path.`,
      );
    }
  }

  const lib = await Deno.dlopen(libPath, {
    net_ping: {
      parameters: ["pointer", "i32", "u32"],
      result: "pointer",
      nonblocking: true,
    },
    net_trace_route: {
      parameters: ["pointer", "i32", "u32"],
      result: "pointer",
      nonblocking: true,
    },
    net_mtr: {
      parameters: ["pointer", "u32"],
      result: "pointer",
      nonblocking: true,
    },
    net_get_interfaces: {
      parameters: [],
      result: "pointer",
      nonblocking: true,
    },
    net_get_interface_details: {
      parameters: [],
      result: "pointer",
      nonblocking: true,
    },
    net_arp_scan: {
      parameters: ["pointer", "u32"],
      result: "pointer",
      nonblocking: true,
    },
    net_sniff: {
      parameters: ["pointer", "pointer", "u32", "i32", "u8"],
      result: "pointer",
      nonblocking: true,
    },
    net_check_port: {
      parameters: ["pointer", "u16", "pointer", "u32"],
      result: "pointer",
      nonblocking: true,
    },
    net_bandwidth_test: {
      parameters: ["pointer", "u16", "pointer", "u32"],
      result: "pointer",
      nonblocking: true,
    },
    net_dns_lookup: {
      parameters: ["pointer", "pointer", "pointer"],
      result: "pointer",
      nonblocking: true,
    },
    net_check_prerequisites: {
      parameters: [],
      result: "pointer",
      nonblocking: true,
    },
    free_string: {
      parameters: ["pointer"],
      result: "void",
      nonblocking: true,
    },
  });

  return {
    symbols: lib.symbols as unknown as FFILibrary,
    close: () => lib.close(),
  };
}

function cStringToString(ptr: Deno.PointerValue): string {
  if (ptr === null) {
    return "";
  }
  const view = new Deno.UnsafePointerView(ptr);
  return view.getCString();
}

export async function callFFIString<T extends unknown[]>(
  lib: FFILibrary,
  fn: (ptr: Deno.PointerValue, ...args: T) => Promise<Deno.PointerValue>,
  str: string,
  ...args: T
): Promise<string> {
  const cstr = encodeCString(str);
  const ptr = Deno.UnsafePointer.of(cstr as BufferSource);
  if (ptr === null) {
    throw new Error("Failed to create C string");
  }
  try {
    const resultPtr = await fn(ptr, ...args);
    if (resultPtr === null) {
      return "";
    }
    const result = cStringToString(resultPtr);
    await lib.free_string(resultPtr);
    return result;
  } finally {
    // Note: We don't free the input string as it's on the stack (JS managed)
  }
}

export async function callFFIStringNullable(
  lib: FFILibrary,
  // deno-lint-ignore no-explicit-any
  fn: (ptr: Deno.PointerValue, ...args: any[]) => Promise<Deno.PointerValue>,
  str: string,
  ...args: (string | null | number | Deno.PointerValue)[]
): Promise<string> {
  const cstr = encodeCString(str);
  const ptr = Deno.UnsafePointer.of(cstr as BufferSource);
  if (ptr === null) {
    throw new Error("Failed to create C string");
  }

  // Keep references to buffers to prevent GC during async FFI call
  // Using a closure that references the buffers ensures they stay alive
  const buffers: Uint8Array[] = [cstr];

  const processedArgs = args.map((arg) => {
    if (typeof arg === "string") {
      const buf = encodeCString(arg);
      buffers.push(buf);
      return Deno.UnsafePointer.of(buf as BufferSource);
    } else if (arg === null) {
      return null;
    }
    return arg;
  });

  // Create a closure that keeps buffers alive - V8 cannot optimize this away
  const keepAlive = () => buffers.length;

  try {
    const resultPtr = await fn(ptr, ...processedArgs);
    // Ensure buffers are still referenced during the async operation
    keepAlive();
    if (resultPtr === null) {
      return "";
    }
    const result = cStringToString(resultPtr);
    await lib.free_string(resultPtr);
    return result;
  } finally {
    // Explicitly keep buffers alive until function returns
    // The closure reference ensures GC doesn't collect them prematurely
    void keepAlive();
  }
}
