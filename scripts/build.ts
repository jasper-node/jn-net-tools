#!/usr/bin/env -S deno run -A

/**
 * Build the jnnt FFI cdylib and stage it in `lib/` as `jnnt-<arch>.<ext>`.
 *
 * Usage:
 *   deno run -A scripts/build.ts --release
 *   deno run -A scripts/build.ts --release --target aarch64-unknown-linux-gnu
 *
 * glibc floor (Linux/gnu targets only): a plain `cargo build` stamps the build
 * host's glibc onto the cdylib, so a library built on a modern CI runner fails
 * to `dlopen` on an older-glibc field device with `version GLIBC_2.xx not
 * found`. Every Linux build therefore links against a floor (default 2.17,
 * override with JN_GLIBC_FLOOR) via `cargo zigbuild --target <triple>.<floor>`,
 * matching JasperNode's own `scripts/release/build_cdylib.ts`. Requires zig +
 * cargo-zigbuild on PATH; the build hard-fails if they are absent rather than
 * silently producing a library the fleet cannot load.
 */

interface TargetShape {
  triple: string;
  arch: string;
  ext: "so" | "dylib" | "dll";
  isLinuxGnu: boolean;
}

function shapeForTriple(triple: string): TargetShape {
  const arch = triple.startsWith("aarch64")
    ? "aarch64"
    : triple.startsWith("x86_64")
    ? "x86_64"
    : null;
  if (!arch) throw new Error(`Unsupported target architecture in triple: ${triple}`);
  const ext = triple.includes("-apple-") ? "dylib" : triple.includes("-windows-") ? "dll" : "so";
  return { triple, arch, ext, isLinuxGnu: triple.endsWith("-unknown-linux-gnu") };
}

function hostTriple(): string {
  const arch = Deno.build.arch;
  switch (Deno.build.os) {
    case "darwin":
      return `${arch}-apple-darwin`;
    case "linux":
      return `${arch}-unknown-linux-gnu`;
    case "windows":
      return `${arch}-pc-windows-msvc`;
    default:
      throw new Error(`Unsupported platform: ${Deno.build.os}`);
  }
}

/** Cargo's own filename for the cdylib, before it is staged with an arch suffix. */
function cargoOutputName(ext: TargetShape["ext"]): string {
  return ext === "dll" ? "jnnt.dll" : `libjnnt.${ext}`;
}

function resolveGlibcFloor(): string | null {
  const raw = (Deno.env.get("JN_GLIBC_FLOOR") ?? "2.17").trim();
  if (raw === "" || raw.toLowerCase() === "none" || raw.toLowerCase() === "off") return null;
  if (!/^\d+\.\d+$/.test(raw)) {
    throw new Error(`JN_GLIBC_FLOOR must look like "2.17" (got "${raw}")`);
  }
  return raw;
}

async function commandSucceeds(cmd: string, args: string[]): Promise<boolean> {
  try {
    const { success } = await new Deno.Command(cmd, { args, stdout: "null", stderr: "null" })
      .output();
    return success;
  } catch {
    return false;
  }
}

async function assertZigbuildAvailable(floor: string): Promise<void> {
  const hasZig = await commandSucceeds("zig", ["version"]);
  // cargo-zigbuild has no --version; --help exits 0 when installed.
  const hasZigbuild = await commandSucceeds("cargo", ["zigbuild", "--help"]);
  if (hasZig && hasZigbuild) return;
  throw new Error(
    `A Linux build must link against the glibc ${floor} floor, which needs zig + cargo-zigbuild:\n` +
      `  missing: ${
        [!hasZig && "zig", !hasZigbuild && "cargo-zigbuild"].filter(Boolean).join(", ")
      }\n` +
      `  install: brew install zig && cargo install cargo-zigbuild\n` +
      `  (or set JN_GLIBC_FLOOR=none to link the host glibc — never ship that build)`,
  );
}

function parseArgs(args: string[]): { release: boolean; target: string | null } {
  let target: string | null = null;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--target") {
      target = args[++i] ?? null;
      if (!target) throw new Error("--target needs a rust triple");
    }
  }
  return { release: args.includes("--release"), target };
}

async function main() {
  const { release, target } = parseArgs(Deno.args);
  const buildDir = release ? "release" : "debug";
  const shape = shapeForTriple(target ?? hostTriple());
  const floor = shape.isLinuxGnu ? resolveGlibcFloor() : null;

  const cargoArgs = [release ? "--release" : null].filter(Boolean) as string[];
  const env: Record<string, string> = {};
  let subcommand = "build";

  if (floor !== null) {
    await assertZigbuildAvailable(floor);
    subcommand = "zigbuild";
    // cargo-zigbuild reads the `.<glibc>` suffix and links that symbol set.
    cargoArgs.push("--target", `${shape.triple}.${floor}`);
    console.log(`Building jnnt for ${shape.triple} against the glibc ${floor} floor...`);
  } else {
    if (target) cargoArgs.push("--target", shape.triple);
    console.log(`Building jnnt for ${shape.triple} (${buildDir})...`);
  }

  const build = await new Deno.Command("cargo", {
    args: [subcommand, "-p", "jnnt", ...cargoArgs],
    env,
    stdout: "inherit",
    stderr: "inherit",
  }).output();
  if (!build.success) {
    console.error("Cargo build failed");
    Deno.exit(1);
  }

  // The `.<glibc>` suffix is a zigbuild hint and never appears in target/.
  const builtForTriple = target !== null || floor !== null;
  const outDir = builtForTriple ? `target/${shape.triple}/${buildDir}` : `target/${buildDir}`;
  const sourcePath = `${outDir}/${cargoOutputName(shape.ext)}`;
  // Windows stages bare — JasperNode's asset convention is a single jnnt.dll.
  const targetPath = shape.ext === "dll" ? "lib/jnnt.dll" : `lib/jnnt-${shape.arch}.${shape.ext}`;

  try {
    await Deno.stat(sourcePath);
  } catch {
    throw new Error(`Built library not found at ${sourcePath}. Build may have failed.`);
  }

  await Deno.mkdir("lib", { recursive: true });
  console.log(`Copying ${sourcePath} → ${targetPath}...`);
  await Deno.copyFile(sourcePath, targetPath);
  if (Deno.build.os !== "windows") await Deno.chmod(targetPath, 0o755);

  console.log(`✅ Staged ${targetPath}${floor !== null ? ` (glibc ${floor} floor)` : ""}`);
}

if (import.meta.main) {
  await main();
}
