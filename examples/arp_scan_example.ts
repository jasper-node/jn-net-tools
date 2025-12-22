import { JNNetTools } from "../src/mod.ts";
import stringify from "json-stringify-pretty-compact";

const tools = new JNNetTools();
await tools.init();

// You may need to specify the interface name, e.g., "en0", "eth0"
const iface = Deno.args[0] || "en0";

console.log(`Scanning ARP on interface ${iface}...`);
try {
  const result = await tools.arpScan(iface, 5000);
  console.log("Result:", stringify(result));
} catch (err) {
  console.error("Error:", err);
}
