import { getFiltersByCategory, getSupportedFilters, isValidFilter } from "../src/filters.ts";

// Example usage of filter API
console.log("=== Supported Filters ===\n");

const filters = getSupportedFilters();
filters.forEach((filter) => {
  console.log(`Pattern: ${filter.pattern}`);
  console.log(`Description: ${filter.description}`);
  if (filter.example) {
    console.log(`Example: ${filter.example}`);
  }
  console.log("");
});

console.log("\n=== Filters by Category ===\n");
const byCategory = getFiltersByCategory();
console.log("Protocols:", byCategory.protocols);
console.log("Ports:", byCategory.ports);
console.log("Hosts:", byCategory.hosts);

console.log("\n=== Filter Validation ===\n");
const testFilters = [
  "tcp",
  "tcp port 443",
  "host 1.1.1.1",
  "invalid filter",
  "",
];

testFilters.forEach((filter) => {
  console.log(`"${filter}" is ${isValidFilter(filter) ? "valid" : "invalid"}`);
});
