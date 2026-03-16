# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`jn-net-tools` is a hybrid Rust + Deno network diagnostics library (`@controlx-io/jn-net-tools` on JSR). Rust provides raw socket operations via FFI (cdylib), while Deno/TypeScript handles high-level protocols (HTTP, WHOIS, DNS) natively. IPv4-only.

## Build & Test Commands

```bash
deno task build          # Run Rust tests then compile Rust FFI library
deno task build:rust     # Compile Rust FFI only (scripts/build.ts --release)
deno task test           # Full suite: check + TypeScript tests + Rust tests
deno task test:ts        # Deno tests only (deno test -A)
deno task test:rust      # Rust tests only (cargo test)
deno task check          # TypeScript type check + format check + lint
deno task lint           # Lint only (ignores test files)

# Run a single TypeScript test file
deno test -A src/__specs__/filters_test.ts

# Run a single Rust test
cargo test -p jnnt test_name
```

## Architecture

### FFI Data Flow

1. TypeScript (`jn_net_tools.ts`) calls FFI functions defined in `ffi.ts`
2. Rust (`src_jnnt/src/lib.rs`) receives C string pointers, runs async work on a Tokio runtime (`runtime.rs`)
3. Results serialize to JSON, returned as C strings (caller frees via `free_string`)
4. TypeScript decodes JSON into typed result interfaces

### Source Layout

- **`src/`** — TypeScript: main class (`jn_net_tools.ts`), FFI bridge (`ffi.ts`), filter patterns (`filters.ts`), native tools (`tools/`)
- **`src/__specs__/`** — Deno tests using `@std/assert`
- **`src_jnnt/`** — Rust FFI library
  - `core/` — ping, traceroute, mtr, dns (ICMP/raw sockets)
  - `l2/` — ARP scan, network interface enumeration
  - `ll/` — platform-specific low-level packet I/O (BPF on macOS, AF_PACKET on Linux, WinSock on Windows, io_uring)
  - `transport/` — port checking, bandwidth testing
  - `sniff/` — packet capture with filter support
- **`lib/`** — compiled platform-specific binaries (`.dylib`/`.so`/`.dll`)
- **`examples/`** — one example script per tool
- **`scripts/`** — build script and pre-built binary downloader

### Deno-Native vs Rust-FFI Tools

Three tools run in pure Deno (no FFI): `checkWeb()` (HTTP), `whois()`, `diagnoseDNS()` — located in `src/tools/`. Everything else goes through Rust FFI.

## Code Conventions

- Prefer `interface` over `type` for object shapes
- TypeScript strict mode with all strict checks enabled
- Formatting: 2-space indent, no tabs, 100-char line width, double quotes, semicolons
- Test complex FFI APIs by creating scratch scripts in `./tmp/` (excluded from lint/publish)
- Always use `deno task build` to compile Rust FFI code

## Platform Notes

- macOS/Linux: most FFI tools require elevated privileges (sudo or `setcap cap_net_raw+ep`)
- Windows: uses native ICMP API (no admin needed for ping/trace/mtr), requires Npcap for packet capture
- Build outputs are architecture-specific: `jnnt-aarch64.dylib`, `jnnt-x86_64.so`, etc.
