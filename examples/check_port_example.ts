import { JNNetTools } from "../src/mod.ts";
import stringify from "json-stringify-pretty-compact";

const tools = new JNNetTools();
await tools.init();

const defaultInterface = await tools.getDefaultInterface();
if (defaultInterface) {
  console.log("Default Interface:", defaultInterface.name);
}

const target = Deno.args[0] || "example.com";
const port = Number(Deno.args[1]) || 80;

console.log(`Checking if ${target}:${port} is open...`);
try {
  let result = await tools.checkPort(target, port, "tcp", 2000);
  console.log("Result 1:", stringify(result));
  result = await tools.checkPort(target, 443, "tcp", 2000);
  console.log("Result 2:", stringify(result));
  result = await tools.checkPort("google.com", 8080, "tcp", 2000);
  console.log("Result 3 for google.com:8080:", stringify(result));
} catch (err) {
  console.error("Error:", err);
}
