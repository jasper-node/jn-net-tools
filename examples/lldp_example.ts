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
const timeoutSec = parseInt(Deno.args[1] || "30");

console.log(`Listening for LLDP neighbors on ${iface} for ${timeoutSec}s...`);
try {
  const result = await tools.lldpDiscover(iface, timeoutSec * 1000);
  console.log("Discovered neighbors:", stringify(result));
} catch (err) {
  console.error("Error:", err);
}

console.log(`\nSending LLDP advertisement on ${iface}...`);
try {
  const sendResult = await tools.lldpSend(iface);
  console.log("Send result:", stringify(sendResult));
} catch (err) {
  console.error("Error:", err);
}
