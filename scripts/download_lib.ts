#!/usr/bin/env -S deno run -A

/**
 * Download script to fetch pre-built FFI binaries from GitHub.
 */

const REPO = "jasper-node/jn-net-tools";
const ASSET_NAME = "lib-binaries.tar.gz";
const LIB_DIR = "lib";

async function downloadAsset(url: string, dest: string) {
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error(`Failed to download ${url}: ${resp.statusText}`);
  }
  const file = await Deno.open(dest, { create: true, write: true });
  await resp.body?.pipeTo(file.writable);
}

async function unzip(zipPath: string, destDir: string) {
  console.log(`Extracting ${zipPath} to ${destDir}...`);
  // Use 'tar' which is available on macOS, Linux, and Windows 10+
  const cmd = new Deno.Command("tar", {
    args: ["-xzf", zipPath, "-C", destDir],
  });
  const { success, stderr } = await cmd.output();
  if (!success) {
    throw new Error(`Failed to extract: ${new TextDecoder().decode(stderr)}`);
  }
}

async function fixNaming(destDir: string) {
  // Handle older releases or inconsistent naming by ensuring filenames match expected ones in ffi.ts
  const files = Deno.readDir(destDir);
  for await (const file of files) {
    if (file.isFile && file.name.startsWith("libjnnt")) {
      const newName = file.name.replace(/^libjnnt/, "jnnt");
      console.log(`Renaming ${file.name} to ${newName}...`);
      await Deno.rename(`${destDir}/${file.name}`, `${destDir}/${newName}`);
    }
  }
}

interface GitHubAsset {
  name: string;
  browser_download_url: string;
}

interface GitHubRelease {
  assets: GitHubAsset[];
}

export async function downloadToLocalLib() {
  console.log(`Fetching latest release for ${REPO}...`);
  const resp = await fetch(`https://api.github.com/repos/${REPO}/releases/latest`, {
    headers: {
      "User-Agent": "Deno-Download-Script",
    },
  });
  if (!resp.ok) {
    console.error("Failed to fetch latest release info");
    Deno.exit(1);
  }

  const release = await resp.json() as GitHubRelease;
  const asset = release.assets.find((a) => a.name === ASSET_NAME);

  if (!asset) {
    console.error(`Could not find asset ${ASSET_NAME} in latest release`);
    Deno.exit(1);
  }

  await Deno.mkdir(LIB_DIR, { recursive: true });

  const tempArchive = `${LIB_DIR}/temp_binaries.tar.gz`;
  console.log(`Downloading ${ASSET_NAME} from ${asset.browser_download_url}...`);
  await downloadAsset(asset.browser_download_url, tempArchive);

  await unzip(tempArchive, LIB_DIR);
  await fixNaming(LIB_DIR);

  await Deno.remove(tempArchive);

  console.log("✅ Successfully downloaded and extracted binaries to lib/");
}

if (import.meta.main) {
  await downloadToLocalLib();
}
