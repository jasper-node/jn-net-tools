import { JNNetTools } from "../src/mod.ts";
import stringify from "json-stringify-pretty-compact";

const tools = new JNNetTools();
await tools.init();

const defaultInterface = await tools.getDefaultInterface();
if (defaultInterface) {
  console.log("Default Interface:", stringify(defaultInterface));
}

const target = Deno.args[0] || "google.com";

console.log(`Tracing route to ${target}...`);
try {
  const result = await tools.traceRoute(target, 15, 2000);
  console.log("Result:", stringify(result));
} catch (err) {
  console.error("Error:", err);
}
