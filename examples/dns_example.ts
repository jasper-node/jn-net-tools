import { JNNetTools } from "../src/mod.ts";
import stringify from "json-stringify-pretty-compact";

const tools = new JNNetTools();
await tools.init();

const defaultInterface = await tools.getDefaultInterface();
if (defaultInterface) {
  console.log("Default Interface:", stringify(defaultInterface));
}

const domain = Deno.args[0] || "google.com";
const server = Deno.args[1]; // Optional custom server

console.log(`--- DNS Lookup for ${domain} ---`);

// 1. Standard Lookup (System Resolver)
console.log("\n1. System Resolver (Default):");
try {
  const result = await tools.dns(domain);
  console.log(stringify(result));
} catch (err) {
  console.error("Error:", err);
}

// 2. Custom Server (if provided or default to 1.1.1.1)
const targetServer = server || "1.1.1.1";
console.log(`\n2. Custom Resolver (${targetServer}):`);
try {
  const result = await tools.dns(domain, targetServer);
  console.log(stringify(result));
} catch (err) {
  console.error("Error:", err);
}

// 3. Specific Record Type (MX)
console.log(`\n3. MX Records (via ${targetServer}):`);
try {
  const result = await tools.dns(domain, targetServer, "MX");
  console.log(stringify(result));
} catch (err) {
  console.error("Error:", err);
}
