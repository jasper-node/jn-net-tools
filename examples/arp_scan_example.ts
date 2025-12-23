import { JNNetTools } from "../src/mod.ts";
import stringify from "json-stringify-pretty-compact";

const tools = new JNNetTools();
await tools.init();

const defaultInterface = await tools.getDefaultInterface();
if (!defaultInterface) {
  console.error("No default interface found");
  Deno.exit(1);
}

const iface = Deno.args[0] || defaultInterface.name;

console.log(`Scanning ARP on interface ${iface}...`);
try {
  const result = await tools.arpScan(iface, 5000);
  console.log("Result:", stringify(result));
} catch (err) {
  console.error("Error:", err);
}
