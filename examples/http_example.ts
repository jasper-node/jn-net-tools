import { JNNetTools } from "../src/mod.ts";
import stringify from "json-stringify-pretty-compact";

const tools = new JNNetTools();
await tools.init();

const url = Deno.args[0] || "https://example.com";

console.log(`Checking HTTP status for ${url}...`);
try {
  const result = await tools.checkWeb(url);
  console.log("Result:", stringify(result));
} catch (err) {
  console.error("Error:", err);
}
