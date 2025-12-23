import { JNNetTools } from "../src/mod.ts";
import stringify from "json-stringify-pretty-compact";

const tools = new JNNetTools();
await tools.init();

console.log("Listing network interfaces...");
try {
  const result = await tools.getNetworkInterfaces();
  console.log("Result:", stringify(result));
} catch (err) {
  console.error("Error:", err);
}
