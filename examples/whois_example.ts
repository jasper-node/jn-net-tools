import { JNNetTools } from "../src/mod.ts";
import stringify from "json-stringify-pretty-compact";

const tools = new JNNetTools();
await tools.init();

const defaultInterface = await tools.getDefaultInterface();
if (defaultInterface) {
  console.log("Default Interface:", stringify(defaultInterface));
}

const domain = Deno.args[0] || "google.com";

console.log(`Performing WHOIS lookup for ${domain}...`);
try {
  const result = await tools.whois(domain);
  console.log("Result:", stringify(result));
} catch (err) {
  console.error("Error:", err);
}
