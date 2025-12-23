import { JNNetTools } from "../src/mod.ts";
import stringify from "json-stringify-pretty-compact";

const tools = new JNNetTools();
await tools.init();

console.log("Listing network interfaces...");
try {
  const prerequisites = await tools.checkPrerequisites();
  console.log("Prerequisites:", stringify(prerequisites));

  const result = await tools.getNetworkInterfaces();
  console.log("Result:", stringify(result));
  const defaultInterface = await tools.getDefaultInterface();
  console.log("Default interface:", stringify(defaultInterface));
} catch (err) {
  console.error("Error:", err);
}
