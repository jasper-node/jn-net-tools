import { JNNetTools } from "../src/mod.ts";
import stringify from "json-stringify-pretty-compact";

const tools = new JNNetTools();
await tools.init();

const defaultInterface = await tools.getDefaultInterface();
if (defaultInterface) {
  console.log("Default Interface:", defaultInterface.name);
}

const target = Deno.args[0] || "example.com";
const port = Number(Deno.args[1]) || 80;

console.log(`Testing bandwidth to ${target}:${port}...`);
try {
  // Note: This requires a server listening on the target port that can handle the test
  // or simple connection throughput. The implementation detail depends on the Rust side.
  // Assuming it acts as a client sending data.
  const result = await tools.bandwidth(target, port, "tcp", 5000);
  console.log("Result:", stringify(result));
} catch (err) {
  console.error("Error:", err);
}
