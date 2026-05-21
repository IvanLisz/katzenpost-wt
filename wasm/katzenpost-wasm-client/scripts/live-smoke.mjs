import { chromium } from "@playwright/test";
import { spawn } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(packageRoot, "..", "..");
const topologyRoot = process.env.KPWT_TOPOLOGY_ROOT
  ? path.resolve(process.env.KPWT_TOPOLOGY_ROOT)
  : path.join(repoRoot, "docker", "voting_mixnet");
const gatewayConfig = path.join(topologyRoot, "gateway1", "katzenpost.toml");
const serviceLog = path.join(topologyRoot, "servicenode1", "katzenpost.log");
const certPath = process.env.KPWT_CERT ?? path.join(topologyRoot, "certs", "katzenpost-wt.crt");
const chromiumPath = process.env.CHROMIUM_PATH ?? "/usr/bin/chromium";
const sphinxMode = process.env.KPWT_SPHINX_MODE ?? "nike";
const kemName = process.env.KPWT_KEM ?? "x25519";
const isKEMSphinx = sphinxMode.toLowerCase().startsWith("kem");
const expectedPacketLength = Number.parseInt(
  process.env.KPWT_PACKET_LEN ?? (isKEMSphinx ? "3402" : "3082"),
  10,
);

function readWebTransportURL() {
  const cfg = readFileSync(gatewayConfig, "utf8");
  const match = cfg.match(/PublicURL\s*=\s*"([^"]+)"/);
  if (!match) {
    throw new Error(`could not find WebTransport PublicURL in ${gatewayConfig}`);
  }
  return match[1];
}

function derCertificateHash(certFile) {
  const pem = readFileSync(certFile, "utf8");
  const body = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  const der = Buffer.from(body, "base64");
  return [...createHash("sha256").update(der).digest()];
}

function spkiHashBase64(certFile) {
  const cert = new X509Certificate(readFileSync(certFile));
  const spki = cert.publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(spki).digest("base64");
}

function rawEd25519PublicKeyFromPem(publicKeyFile) {
  const pem = readFileSync(publicKeyFile, "utf8");
  const body = pem
    .replace(/-----BEGIN ED25519 PUBLIC KEY-----/g, "")
    .replace(/-----END ED25519 PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");
  const raw = Buffer.from(body, "base64");
  if (raw.byteLength !== 32) {
    throw new Error(`expected 32-byte Ed25519 key in ${publicKeyFile}, got ${raw.byteLength}`);
  }
  return raw;
}

function readTrustAnchors() {
  const authDirs = readdirSync(topologyRoot)
    .filter((name) => /^auth\d+$/.test(name))
    .sort((a, b) => Number(a.slice(4)) - Number(b.slice(4)));
  if (authDirs.length === 0) {
    throw new Error(`no auth directories found under ${topologyRoot}`);
  }
  return Buffer.concat(
    authDirs.map((dir) => rawEd25519PublicKeyFromPem(path.join(topologyRoot, dir, "identity.public.pem"))),
  );
}

function epochCandidates() {
  const katzenpostEpochStart = Date.UTC(2017, 5, 1, 0, 0, 0);
  const warpedPeriodMs = 2 * 60 * 1000;
  const current = Math.floor((Date.now() - katzenpostEpochStart) / warpedPeriodMs);
  const out = [current];
  for (let delta = 1; delta <= 6; delta += 1) {
    out.push(current - delta, current + delta);
  }
  return out;
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => resolve(address.port));
    });
  });
}

async function waitForHTTP(url, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      await new Promise((resolve, reject) => {
        const req = http.get(url, (res) => {
          res.resume();
          if (res.statusCode && res.statusCode < 500) {
            resolve();
          } else {
            reject(new Error(`HTTP ${res.statusCode}`));
          }
        });
        req.once("error", reject);
        req.setTimeout(1000, () => req.destroy(new Error("timeout")));
      });
      return;
    } catch (err) {
      lastError = err;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
  throw lastError ?? new Error(`timed out waiting for ${url}`);
}

function fileOffset(file) {
  if (!existsSync(file)) {
    return 0;
  }
  return readFileSync(file).byteLength;
}

async function waitForLogPattern(file, pattern, offset, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(file)) {
      const current = readFileSync(file).subarray(offset).toString("utf8");
      const match = current.match(pattern);
      if (match) {
        return match[0];
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`timed out waiting for ${pattern} in ${file}`);
}

async function main() {
  if (!existsSync(chromiumPath)) {
    throw new Error(`Chromium executable not found at ${chromiumPath}`);
  }
  if (!existsSync(gatewayConfig)) {
    throw new Error(`gateway config not found at ${gatewayConfig}`);
  }
  if (!existsSync(certPath)) {
    throw new Error(`certificate not found at ${certPath}`);
  }

  const webTransportURL = readWebTransportURL();
  const wtURL = new URL(webTransportURL);
  const certHash = derCertificateHash(certPath);
  const spkiHash = spkiHashBase64(certPath);
  const trustAnchors = [...readTrustAnchors()];
  const threshold = Math.floor(trustAnchors.length / 32 / 2) + 1;
  const epochs = epochCandidates();
  const vitePort = await getFreePort();
  const serviceLogOffset = fileOffset(serviceLog);

  const vite = spawn(
    process.execPath,
    [
      path.join(packageRoot, "node_modules", "vite", "bin", "vite.js"),
      "web",
      "--host",
      "127.0.0.1",
      "--port",
      String(vitePort),
      "--strictPort",
    ],
    { cwd: packageRoot, stdio: ["ignore", "pipe", "pipe"] },
  );

  let viteOutput = "";
  vite.stdout.on("data", (chunk) => {
    viteOutput += chunk;
  });
  vite.stderr.on("data", (chunk) => {
    viteOutput += chunk;
  });

  let browser;
  try {
    await waitForHTTP(`http://127.0.0.1:${vitePort}/`);

    browser = await chromium.launch({
      executablePath: chromiumPath,
      headless: true,
      args: [
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--enable-experimental-web-platform-features",
        "--ignore-certificate-errors",
        `--ignore-certificate-errors-spki-list=${spkiHash}`,
        `--origin-to-force-quic-on=${wtURL.host}`,
      ],
    });

    const page = await browser.newPage({ ignoreHTTPSErrors: true });
    page.on("console", (msg) => {
      if (msg.type() === "error") {
        console.error(`[browser:${msg.type()}] ${msg.text()}`);
      }
    });
    page.on("pageerror", (err) => {
      console.error(`[browser:pageerror] ${err.message}`);
    });

    await page.goto(`http://127.0.0.1:${vitePort}/`, { waitUntil: "domcontentloaded" });

    const result = await page.evaluate(
      async ({ url, certHash, trustAnchors, threshold, epochs, isKEMSphinx, kemName, sphinxMode }) => {
        const mod = await import("/index.ts");
        const options = {
          serverCertificateHashes: [{ algorithm: "sha-256", value: new Uint8Array(certHash) }],
        };
        const proof = await mod.proofOfTransport(url, new TextEncoder().encode("dummy"), options);
        const anchors = new Uint8Array(trustAnchors);
        const failures = [];
        const withTimeout = (promise, message, timeoutMs = 45_000) =>
          Promise.race([
            promise,
            new Promise((_, reject) => setTimeout(() => reject(new Error(message)), timeoutMs)),
          ]);

        for (const epoch of epochs) {
          try {
            const checked = await mod.fetchAndVerifyConsensus(
              url,
              BigInt(epoch),
              anchors,
              threshold,
              1n,
              options,
            );
            if (checked.state !== "valid" || !checked.consensus) {
              failures.push(`epoch ${epoch}: ${checked.state}${checked.error ? `: ${checked.error}` : ""}`);
              continue;
            }
            const buildPacket = isKEMSphinx ? mod.buildKEMSphinxPacket : mod.buildSphinxPacket;
            const buildPacketWithSURB = isKEMSphinx ? mod.buildKEMSphinxPacketWithSURB : mod.buildSphinxPacketWithSURB;
            const packetPayload = new TextEncoder().encode("mvp3-live-smoke");
            const packet = isKEMSphinx
              ? await buildPacket(
                  checked.rawConsensus,
                  anchors,
                  threshold,
                  BigInt(checked.consensus.epoch),
                  url,
                  "echo",
                  packetPayload,
                  kemName,
                )
              : await buildPacket(
                  checked.rawConsensus,
                  anchors,
                  threshold,
                  BigInt(checked.consensus.epoch),
                  url,
                  "echo",
                  packetPayload,
                );
            const ack = await mod.sendSphinxPacket(url, packet, options);
            const replyRequestPayload = new TextEncoder().encode("mvp4-live-smoke");
            const withSurb = isKEMSphinx
              ? await buildPacketWithSURB(
                  checked.rawConsensus,
                  anchors,
                  threshold,
                  BigInt(checked.consensus.epoch),
                  url,
                  "echo",
                  replyRequestPayload,
                  kemName,
                )
              : await buildPacketWithSURB(
                  checked.rawConsensus,
                  anchors,
                  threshold,
                  BigInt(checked.consensus.epoch),
                  url,
                  "echo",
                  replyRequestPayload,
                );
            const replyCiphertext = await mod.sendSphinxPacketAndWaitReply(
              url,
              new Uint8Array(withSurb.packet),
              new Uint8Array(withSurb.recipient),
              options,
            );
            const replyPlaintext = await mod.decryptSurbReply(
              replyCiphertext,
              new Uint8Array(withSurb.surb_keys),
            );
            const replyText = new TextDecoder().decode(replyPlaintext.subarray(0, replyRequestPayload.byteLength));
            const asyncReplyRequestPayload = new TextEncoder().encode("mvp5-live-smoke");
            const withAsyncSurb = isKEMSphinx
              ? await buildPacketWithSURB(
                  checked.rawConsensus,
                  anchors,
                  threshold,
                  BigInt(checked.consensus.epoch),
                  url,
                  "echo",
                  asyncReplyRequestPayload,
                  kemName,
                )
              : await buildPacketWithSURB(
                  checked.rawConsensus,
                  anchors,
                  threshold,
                  BigInt(checked.consensus.epoch),
                  url,
                  "echo",
                  asyncReplyRequestPayload,
                );
            const receiver = await mod.openOnlineSurbReceiver(
              url,
              new Uint8Array(withAsyncSurb.recipient),
              options,
            );
            let asyncPacketAck;
            let asyncReplyCiphertext;
            try {
              asyncPacketAck = await mod.sendSphinxPacket(url, new Uint8Array(withAsyncSurb.packet), options);
              asyncReplyCiphertext = await withTimeout(receiver.nextReply(), "timed out waiting for MVP5 online reply");
            } finally {
              await receiver.close();
            }
            const asyncReplyPlaintext = await mod.decryptSurbReply(
              asyncReplyCiphertext,
              new Uint8Array(withAsyncSurb.surb_keys),
            );
            const asyncReplyText = new TextDecoder().decode(
              asyncReplyPlaintext.subarray(0, asyncReplyRequestPayload.byteLength),
            );
            return {
              sphinxMode,
              kemName: isKEMSphinx ? kemName : "",
              proofText: proof.text,
              epoch: checked.consensus.epoch.toString(),
              expiration: checked.consensus.expiration.toString(),
              signatures: checked.consensus.signatures_verified,
              gateways: checked.consensus.webtransport_gateways,
              packetLength: packet.byteLength,
              packetAck: ack.text,
              replyCiphertextLength: replyCiphertext.byteLength,
              replyPlaintextLength: replyPlaintext.byteLength,
              replyText,
              asyncPacketAck: asyncPacketAck.text,
              asyncReplyCiphertextLength: asyncReplyCiphertext.byteLength,
              asyncReplyPlaintextLength: asyncReplyPlaintext.byteLength,
              asyncReplyText,
            };
          } catch (err) {
            failures.push(`epoch ${epoch}: ${err instanceof Error ? err.message : String(err)}`);
          }
        }
        throw new Error(`no valid consensus found; ${failures.join("; ")}`);
      },
      { url: webTransportURL, certHash, trustAnchors, threshold, epochs, isKEMSphinx, kemName, sphinxMode },
    );

    if (!result.proofText.startsWith("katzenpost-wt-ok")) {
      throw new Error(`unexpected proof response: ${result.proofText}`);
    }
    if (!result.gateways.some((gateway) => gateway.endpoints.includes(webTransportURL))) {
      throw new Error(`verified consensus does not advertise ${webTransportURL}`);
    }
    if (result.packetLength !== expectedPacketLength) {
      throw new Error(`unexpected Sphinx packet length: ${result.packetLength}`);
    }
    if (result.packetAck !== "accepted") {
      throw new Error(`unexpected packet ack: ${result.packetAck}`);
    }
    if (result.replyText !== "mvp4-live-smoke") {
      throw new Error(`unexpected SURB reply text: ${result.replyText}`);
    }
    if (result.asyncPacketAck !== "accepted") {
      throw new Error(`unexpected async packet ack: ${result.asyncPacketAck}`);
    }
    if (result.asyncReplyText !== "mvp5-live-smoke") {
      throw new Error(`unexpected online SURB reply text: ${result.asyncReplyText}`);
    }

    result.serviceLog = await waitForLogPattern(
      serviceLog,
      /Processed Kaetzchen request: .* \(No response\)/,
      serviceLogOffset,
    );

    console.log(JSON.stringify(result, null, 2));
  } catch (err) {
    if (viteOutput.trim()) {
      console.error(viteOutput.trim());
    }
    throw err;
  } finally {
    if (browser) {
      await browser.close();
    }
    vite.kill("SIGTERM");
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
