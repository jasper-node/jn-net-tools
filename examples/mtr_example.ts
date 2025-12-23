import { JNNetTools } from "../src/mod.ts";
import stringify from "json-stringify-pretty-compact";

const tools = new JNNetTools();
await tools.init();

const defaultInterface = await tools.getDefaultInterface();
if (defaultInterface) {
  console.log("Default Interface:", defaultInterface.name);
}

const target = Deno.args[0] || "8.8.8.8";
const duration = 5000;

console.log(`Running MTR against ${target} for ${duration}ms...`);
try {
  const result = await tools.mtr(target, duration);
  console.log("Result:", stringify(result));
} catch (err) {
  console.error("Error:", err);
}
