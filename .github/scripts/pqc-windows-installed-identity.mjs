import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import fs from "node:fs";
import { createRequire } from "node:module";
import net from "node:net";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

const root = fs.realpathSync(process.argv[2]);
assert.equal(process.platform + "/" + process.arch, "win32/x64");
assert.match(path.basename(root), /^pqc-windows-install-[a-z0-9]+$/i);
const packagePath = fs.realpathSync(process.argv[3]);
const sri = "sha512-" + createHash("sha512").update(fs.readFileSync(packagePath)).digest("base64");
const lock = JSON.parse(fs.readFileSync(path.join(root, "package-lock.json"), "utf8"));
assert.equal(lock.packages["node_modules/openclaw"].integrity, sri);
const product = path.join(root, "node_modules", "openclaw");
const cli = path.join(product, "openclaw.mjs");
const buildInfo = JSON.parse(
  fs.readFileSync(path.join(product, "dist", "build-info.json"), "utf8"),
);
assert.match(process.env.PQC_SOURCE_SHA ?? "", /^[a-f0-9]{40}$/);
assert.equal(buildInfo.commit, process.env.PQC_SOURCE_SHA);
assert.equal(fs.statSync(cli).isFile(), true);
const requireFromProduct = createRequire(path.join(product, "package.json"));
const permissionEntry = requireFromProduct.resolve("@openclaw/fs-safe/permissions");
const safeDist = path.dirname(permissionEntry);
assert.equal(
  JSON.parse(fs.readFileSync(path.join(safeDist, "..", "package.json"), "utf8")).version,
  "0.12.0",
);
const { readOwnerAndDacl } = await import(pathToFileURL(permissionEntry));
assert.equal(readOwnerAndDacl(root).status, "supported");
const scratch = fs.mkdtempSync(path.join(root, "identity-smoke-"));
const state = path.join(scratch, "state");
const tmp = path.join(scratch, "temp");
fs.mkdirSync(tmp);
fs.mkdirSync(state);
const config = path.join(state, "openclaw.json");
const wrapKey = path.join(state, "wrap-key.b64");
const identityDb = path.join(state, "state", "openclaw.sqlite");
fs.writeFileSync(
  config,
  JSON.stringify({
    gateway: { mode: "local", auth: { mode: "token" }, controlUi: { enabled: false } },
  }),
  { flag: "wx" },
);
const digest = (p) => createHash("sha256").update(fs.readFileSync(p)).digest("hex");
const nativePackage = "@openclaw/fs-safe-win32-x64-msvc";
const nativeEntry = createRequire(path.join(product, "dist", "index.js")).resolve(nativePackage);
assert.equal(path.basename(nativeEntry), "fs-safe-native.node");
const nativeRoot = path.dirname(nativeEntry);
const nativeKey = path.relative(root, nativeRoot).split(path.sep).join("/");
assert.match(nativeKey, /^node_modules\//);
assert.equal(
  JSON.parse(fs.readFileSync(path.join(nativeRoot, "package.json"), "utf8")).version,
  "0.12.0",
);
assert.equal(
  lock.packages[nativeKey]?.integrity,
  "sha512-hI+0jj3uwl6iWlOLu6bYAfaUzYwITIeM8z5P38mY59vnVppduBHyomKwsuO/aW6xsNKwR9rDH/FrsLbiTyZW/A==",
);
assert.equal(
  digest(nativeEntry),
  "9b8946fd4217a0e34f2a1e0e4c84ac979d4ab2514baf6d048a328f709dd5e96a",
);
console.log("INSTALLED_MATCHING_WINDOWS_NATIVE_OPTIONAL_PACKAGE=PASS");
const exec = promisify(execFile);
const token = randomBytes(32).toString("base64url");
const systemVars =
  /^(Path|SystemRoot|ComSpec|windir|ProgramData|PATHEXT|USERNAME|OS|PROCESSOR_ARCHITECTURE|NUMBER_OF_PROCESSORS|LANG|LC_ALL)$/i;
const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => systemVars.test(k)));
Object.assign(env, {
  HOME: root,
  USERPROFILE: root,
  APPDATA: tmp,
  LOCALAPPDATA: tmp,
  TEMP: tmp,
  TMP: tmp,
  TMPDIR: tmp,
  NODE_DISABLE_COMPILE_CACHE: "1",
  OPENCLAW_HOME: root,
  OPENCLAW_STATE_DIR: state,
  OPENCLAW_CONFIG_PATH: config,
  OPENCLAW_GATEWAY_TOKEN: token,
  OPENCLAW_DISABLE_BONJOUR: "1",
  OPENCLAW_SKIP_CHANNELS: "1",
  OPENCLAW_SKIP_CRON: "1",
  NO_PROXY: "127.0.0.1,localhost",
});

async function withGateway(work) {
  const reserve = net.createServer().listen(0, "127.0.0.1");
  await once(reserve, "listening");
  const port = String(reserve.address().port);
  await new Promise((resolve, reject) => reserve.close((e) => (e ? reject(e) : resolve())));
  const child = spawn(
    process.execPath,
    [cli, "gateway", "run", "--bind", "loopback", "--port", port],
    { cwd: root, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] },
  );
  const closed = once(child, "close");
  let output = "";
  const preserve = (chunk) => {
    output = (output + String(chunk)).slice(-12000);
  };
  child.stdout.on("data", preserve);
  child.stderr.on("data", preserve);
  const invoke = (parts) =>
    exec(
      process.execPath,
      [cli, "gateway", ...parts, "--port", port, "--timeout", "6500", "--json"],
      { cwd: root, env, windowsHide: true, timeout: 25000, maxBuffer: 1024 * 1024 },
    );
  const redact = (s) => String(s ?? "").replaceAll(token, "[REDACTED]");
  try {
    const deadline = Date.now() + 120000;
    let health;
    let lastError;
    while (Date.now() < deadline && child.exitCode === null) {
      if (!/listening|gateway.*ready/i.test(output)) {
        await delay(500);
        continue;
      }
      try {
        health = JSON.parse((await invoke(["health"])).stdout);
        if (health.ok === true) break;
      } catch (error) {
        lastError = error;
      }
      await delay(500);
    }
    if (health?.ok !== true) {
      throw new Error(
        redact([lastError?.stderr, lastError?.stdout, output].filter(Boolean).join("\n")),
      );
    }
    assert.match(output, /\bmemory-core\b/);
    await work(async () => {
      try {
        return {
          ok: true,
          identity: JSON.parse((await invoke(["call", "gateway.identity.get"])).stdout),
        };
      } catch (error) {
        return {
          ok: false,
          details: redact([error.message, error.stderr, error.stdout, output].join("\n")),
        };
      }
    });
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await closed;
  }
}
function validateIdentity(result) {
  if (!result.ok) throw new Error(result.details);
  const { deviceId, publicKey } = result.identity;
  assert.match(deviceId, /^[a-f0-9]{64}$/);
  assert.equal(Buffer.from(publicKey, "base64url").length, 1952);
  return { deviceId, publicKey };
}
let initial;
let keyDigest;
assert.equal(fs.existsSync(wrapKey), false);
await withGateway(async (callIdentity) => {
  initial = validateIdentity(await callIdentity());
});
console.log("INSTALLED_GATEWAY_HEALTH_AND_FIRST_ML_DSA_IDENTITY=PASS");
assert.equal(fs.statSync(identityDb).isFile(), true);
assert.equal(fs.statSync(wrapKey).isFile(), true);
assert.equal(readOwnerAndDacl(wrapKey).status, "supported");
keyDigest = digest(wrapKey);
async function readIdentityInNewCli(nativeMode) {
  const childEnv = { ...env };
  if (nativeMode) childEnv.FS_SAFE_NATIVE_MODE = nativeMode;
  try {
    const result = await exec(process.execPath, [cli, "node", "identity", "--json"], {
      env: childEnv,
      cwd: root,
      windowsHide: true,
      timeout: 45000,
      maxBuffer: 1024 * 1024,
    });
    return { ok: true, identity: JSON.parse(result.stdout) };
  } catch (error) {
    return {
      ok: false,
      details: [error.message, error.stderr, error.stdout]
        .join("\n")
        .replaceAll(token, "[REDACTED]"),
    };
  }
}
{
  assert.deepEqual(validateIdentity(await readIdentityInNewCli(undefined)), initial);
  assert.equal(digest(wrapKey), keyDigest);
  console.log("INSTALLED_NEW_CLI_PROCESS_IDENTITY_AND_KEY_RELOAD=PASS");
}
{
  const result = await readIdentityInNewCli("off");
  assert.equal(result.ok, false);
  if (
    !/helper-unavailable|Windows owner and DACL facts require the matching optional native platform package/i.test(
      result.details,
    )
  )
    throw new Error(result.details);
  assert.equal(digest(wrapKey), keyDigest);
  console.log("INSTALLED_CLI_NATIVE_OFF_REFUSES_IDENTITY_WITHOUT_KEY_CHANGE=PASS");
}
