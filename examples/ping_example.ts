import { JNNetTools } from "../src/mod.ts";
import stringify from "json-stringify-pretty-compact";

const tools = new JNNetTools();
await tools.init();

const target = Deno.args[0] || "8.8.8.8";

console.log(`Pinging ${target}...`);
try {
  const result = await tools.ping(target, 4, 1000);
  console.log("Result:", stringify(result));
} catch (err) {
  console.error("Error:", err);
}
