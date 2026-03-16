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

console.log(`Scanning for PROFINET devices on ${iface}...`);
try {
  const result = await tools.dcpIdentify(iface, 5000);
  console.log("Discovered devices:", stringify(result));

  if (result.devices.length > 0 && result.devices[0]) {
    console.log(`\nReading parameters from ${result.devices[0].mac}...`);
    const getResult = await tools.dcpGet(iface, result.devices[0].mac, 3000);
    console.log("Device details:", stringify(getResult));
  }
} catch (err) {
  console.error("Error:", err);
}
