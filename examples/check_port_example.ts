import { JNNetTools } from "../src/mod.ts";
import stringify from "json-stringify-pretty-compact";

const tools = new JNNetTools();
await tools.init();

const target = Deno.args[0] || "google.com";
const port = Number(Deno.args[1]) || 80;

console.log(`Checking if ${target}:${port} is open...`);
try {
  const result = await tools.checkPort(target, port, "tcp", 2000);
  console.log("Result:", stringify(result));
} catch (err) {
  console.error("Error:", err);
}
