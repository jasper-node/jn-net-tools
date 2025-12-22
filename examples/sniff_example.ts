import { JNNetTools } from "../src/mod.ts";
import stringify from "json-stringify-pretty-compact";

const tools = new JNNetTools();
await tools.init();

const iface = Deno.args[0] || "en0";
// const filter = Deno.args[1] || "tcp port 80";
const filter = Deno.args[1] || "tcp";

console.log(`Sniffing on ${iface} with filter "${filter}"...`);
try {
  const result = await tools.sniff(iface, filter, 5000, 10);
  console.log("Result:", stringify(result));
} catch (err) {
  console.error("Error:", err);
}
