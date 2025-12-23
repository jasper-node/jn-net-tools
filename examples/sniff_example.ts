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
// const filter = Deno.args[1] || "tcp port 80";
const filter = Deno.args[1] || "tcp";

console.log(`Sniffing on ${iface} with filter "${filter}"...`);
try {
  const result = await tools.sniff(iface, filter, 3000, 5);
  console.log("Result:", stringify(result));

  const result2 = await tools.sniff(iface, filter, 3000, 5, true);
  console.log("Result with data:", stringify(result2));
} catch (err) {
  console.error("Error:", err);
}
