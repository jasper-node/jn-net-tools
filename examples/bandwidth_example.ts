import { JNNetTools } from "../src/mod.ts";
import stringify from "json-stringify-pretty-compact";

const PORT = 8092;

function startEchoServer() {
  const listener = Deno.listen({ port: PORT });
  console.log(`Local Echo Server listening on port ${PORT}...`);

  // Handle connections in background
  (async () => {
    for await (const conn of listener) {
      // Echo data back to test bidirectional throughput
      try {
        const buf = new Uint8Array(32 * 1024);
        while (true) {
          const n = await conn.read(buf);
          if (n === null || n === 0) break;
          // Echo the data back
          await conn.write(buf.subarray(0, n));
        }
      } catch {
        // Ignore errors
      } finally {
        try {
          conn.close();
        } catch {
          // Ignore close errors
        }
      }
    }
  })();

  return listener;
}

const tools = new JNNetTools();
await tools.init();

const defaultInterface = await tools.getDefaultInterface();
if (defaultInterface) {
  console.log("Default Interface:", defaultInterface.name);
}

// Allow command-line args for custom targets, but default to local server
const useLocalServer = !Deno.args[0];
let server: Deno.Listener | null = null;

if (useLocalServer) {
  server = startEchoServer();
  // Give server a moment to start
  await new Promise((resolve) => setTimeout(resolve, 100));
}

const target = Deno.args[0] || "127.0.0.1";
const port = Number(Deno.args[1]) || PORT;

console.log(`Testing bandwidth to ${target}:${port}...`);
try {
  const result = await tools.bandwidth(target, port, "tcp", 5000);
  console.log("Result:", stringify(result));
} catch (err) {
  console.error("Error:", err);
} finally {
  if (server) {
    server.close();
  }
}
