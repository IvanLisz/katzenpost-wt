import init, {
  build_kemsphinx_packet,
  build_kemsphinx_packet_with_surb,
  build_sphinx_packet,
  build_sphinx_packet_with_surb,
  check_consensus,
  decrypt_surb_reply,
  encode_get_consensus2,
  verify_consensus,
} from "./pkg/katzenpost_wasm_client";

const FRAME_MAGIC = new Uint8Array([0x4b, 0x50, 0x57, 0x54]); // KPWT
const FRAME_VERSION = 1;
const FRAME_HEADER_LEN = 12;
const FRAME_PING = 1;
const FRAME_GET_CONSENSUS = 2;
const FRAME_SEND_PACKET = 3;
const FRAME_SEND_PACKET_WITH_REPLY = 4;
const FRAME_REGISTER_RECEIVER = 5;
const FRAME_PONG = 0x81;
const FRAME_CONSENSUS = 0x82;
const FRAME_PACKET_ACK = 0x83;
const FRAME_SURB_REPLY = 0x84;
const FRAME_RECEIVER_ACK = 0x85;
const STATUS_OK = 0;
const RECIPIENT_ID_LEN = 32;

export interface ConsensusStatus {
  epoch: bigint;
  expiration: bigint;
  signatures_verified: number;
  webtransport_gateways: Array<{ name: string; endpoints: string[] }>;
}

export interface ConsensusCheckStatus {
  state: "valid" | "invalid" | "stale";
  error?: string;
  consensus?: ConsensusStatus;
}

export interface SphinxPacketWithSURB {
  packet: Uint8Array;
  recipient: Uint8Array;
  surb_id: Uint8Array;
  surb_keys: Uint8Array;
}

export interface OnlineSurbReceiver {
  recipient: Uint8Array;
  nextReply(): Promise<Uint8Array>;
  close(): Promise<void>;
}

interface ControlFrame {
  type: number;
  status: number;
  payload: Uint8Array;
}

class StreamByteReader {
  private chunks: Uint8Array[] = [];
  private total = 0;

  constructor(private readonly reader: ReadableStreamDefaultReader<Uint8Array>) {}

  async readExact(length: number): Promise<Uint8Array> {
    while (this.total < length) {
      const { value, done } = await this.reader.read();
      if (done || !value) {
        throw new Error("WebTransport stream closed");
      }
      this.chunks.push(value);
      this.total += value.byteLength;
    }

    const out = new Uint8Array(length);
    let offset = 0;
    while (offset < length) {
      const head = this.chunks[0];
      const take = Math.min(head.byteLength, length - offset);
      out.set(head.subarray(0, take), offset);
      offset += take;
      if (take === head.byteLength) {
        this.chunks.shift();
      } else {
        this.chunks[0] = head.subarray(take);
      }
      this.total -= take;
    }
    return out;
  }

  async cancel(): Promise<void> {
    await this.reader.cancel().catch(() => undefined);
  }
}

async function openKatzenpostWebTransportSession(
  url: string,
  options?: WebTransportOptions,
): Promise<{ transport: WebTransport; stream: WebTransportBidirectionalStream }> {
  const transport = new WebTransport(url, options);
  await transport.ready;
  return { transport, stream: await transport.createBidirectionalStream() };
}

export async function openKatzenpostWebTransport(
  url: string,
  options?: WebTransportOptions,
): Promise<WebTransportBidirectionalStream> {
  return (await openKatzenpostWebTransportSession(url, options)).stream;
}

export async function verifyRawConsensus(
  rawConsensus: Uint8Array,
  ed25519TrustAnchors: Uint8Array,
  threshold: number,
  currentEpoch: bigint,
  maxFutureEpochs = 1n,
): Promise<ConsensusStatus> {
  await init();
  return verify_consensus(rawConsensus, ed25519TrustAnchors, threshold, currentEpoch, maxFutureEpochs) as ConsensusStatus;
}

export async function checkRawConsensus(
  rawConsensus: Uint8Array,
  ed25519TrustAnchors: Uint8Array,
  threshold: number,
  currentEpoch: bigint,
  maxFutureEpochs = 1n,
): Promise<ConsensusCheckStatus> {
  await init();
  return check_consensus(rawConsensus, ed25519TrustAnchors, threshold, currentEpoch, maxFutureEpochs) as ConsensusCheckStatus;
}

export async function buildSphinxPacket(
  rawConsensus: Uint8Array,
  ed25519TrustAnchors: Uint8Array,
  threshold: number,
  currentEpoch: bigint,
  gatewayEndpoint: string,
  serviceCapability: string,
  payload: Uint8Array,
  maxFutureEpochs = 1n,
): Promise<Uint8Array> {
  await init();
  return build_sphinx_packet(
    rawConsensus,
    ed25519TrustAnchors,
    threshold,
    currentEpoch,
    maxFutureEpochs,
    gatewayEndpoint,
    serviceCapability,
    payload,
  );
}

export async function buildSphinxPacketWithSURB(
  rawConsensus: Uint8Array,
  ed25519TrustAnchors: Uint8Array,
  threshold: number,
  currentEpoch: bigint,
  gatewayEndpoint: string,
  serviceCapability: string,
  payload: Uint8Array,
  maxFutureEpochs = 1n,
): Promise<SphinxPacketWithSURB> {
  await init();
  return build_sphinx_packet_with_surb(
    rawConsensus,
    ed25519TrustAnchors,
    threshold,
    currentEpoch,
    maxFutureEpochs,
    gatewayEndpoint,
    serviceCapability,
    payload,
  ) as SphinxPacketWithSURB;
}

export async function buildKEMSphinxPacket(
  rawConsensus: Uint8Array,
  ed25519TrustAnchors: Uint8Array,
  threshold: number,
  currentEpoch: bigint,
  gatewayEndpoint: string,
  serviceCapability: string,
  payload: Uint8Array,
  kemName = "x25519",
  maxFutureEpochs = 1n,
): Promise<Uint8Array> {
  await init();
  return build_kemsphinx_packet(
    rawConsensus,
    ed25519TrustAnchors,
    threshold,
    currentEpoch,
    maxFutureEpochs,
    kemName,
    gatewayEndpoint,
    serviceCapability,
    payload,
  );
}

export async function buildKEMSphinxPacketWithSURB(
  rawConsensus: Uint8Array,
  ed25519TrustAnchors: Uint8Array,
  threshold: number,
  currentEpoch: bigint,
  gatewayEndpoint: string,
  serviceCapability: string,
  payload: Uint8Array,
  kemName = "x25519",
  maxFutureEpochs = 1n,
): Promise<SphinxPacketWithSURB> {
  await init();
  return build_kemsphinx_packet_with_surb(
    rawConsensus,
    ed25519TrustAnchors,
    threshold,
    currentEpoch,
    maxFutureEpochs,
    kemName,
    gatewayEndpoint,
    serviceCapability,
    payload,
  ) as SphinxPacketWithSURB;
}

export async function decryptSurbReply(replyPayload: Uint8Array, surbKeys: Uint8Array): Promise<Uint8Array> {
  await init();
  return decrypt_surb_reply(replyPayload, surbKeys);
}

function encodeFrame(
  type: number,
  payload: Uint8Array = new Uint8Array(),
  status = STATUS_OK,
): Uint8Array<ArrayBuffer> {
  const frame = new Uint8Array(new ArrayBuffer(FRAME_HEADER_LEN + payload.byteLength));
  frame.set(FRAME_MAGIC, 0);
  frame[4] = FRAME_VERSION;
  frame[5] = type;
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  view.setUint16(6, status);
  view.setUint32(8, payload.byteLength);
  frame.set(payload, FRAME_HEADER_LEN);
  return frame;
}

async function writeFrame(writer: WritableStreamDefaultWriter<Uint8Array>, frame: ControlFrame): Promise<void> {
  await writer.write(encodeFrame(frame.type, frame.payload, frame.status));
}

async function readFrame(reader: StreamByteReader): Promise<ControlFrame> {
  const header = await reader.readExact(FRAME_HEADER_LEN);
  for (let i = 0; i < FRAME_MAGIC.byteLength; i++) {
    if (header[i] !== FRAME_MAGIC[i]) {
      throw new Error("invalid Katzenpost WT frame magic");
    }
  }
  if (header[4] !== FRAME_VERSION) {
    throw new Error(`unsupported Katzenpost WT frame version ${header[4]}`);
  }
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  const payloadLen = view.getUint32(8);
  return {
    type: header[5],
    status: view.getUint16(6),
    payload: await reader.readExact(payloadLen),
  };
}

export async function proofOfTransport(
  url: string,
  payload = new TextEncoder().encode("dummy"),
  options?: WebTransportOptions,
) {
  const stream = await openKatzenpostWebTransport(url, options);
  const writer = stream.writable.getWriter();
  const reader = new StreamByteReader(stream.readable.getReader());
  try {
    await writeFrame(writer, { type: FRAME_PING, status: STATUS_OK, payload });
    const response = await readFrame(reader);
    if (response.type !== FRAME_PONG || response.status !== STATUS_OK) {
      throw new Error(`unexpected ping response type=${response.type} status=${response.status}`);
    }
    return {
      ok: true,
      response: response.payload,
      text: new TextDecoder().decode(response.payload),
    };
  } finally {
    writer.releaseLock();
    await stream.writable.close().catch(() => undefined);
  }
}

export async function fetchConsensus(
  url: string,
  epoch: bigint,
  options?: WebTransportOptions,
): Promise<Uint8Array> {
  const stream = await openKatzenpostWebTransport(url, options);
  const writer = stream.writable.getWriter();
  const reader = new StreamByteReader(stream.readable.getReader());
  const payload = new Uint8Array(8);
  new DataView(payload.buffer).setBigUint64(0, epoch);
  try {
    await writeFrame(writer, { type: FRAME_GET_CONSENSUS, status: STATUS_OK, payload });
    const response = await readFrame(reader);
    if (response.type !== FRAME_CONSENSUS) {
      throw new Error(`unexpected consensus response type=${response.type}`);
    }
    if (response.status !== STATUS_OK) {
      throw new Error(`gateway returned consensus status ${response.status}`);
    }
    return response.payload;
  } finally {
    writer.releaseLock();
    await stream.writable.close().catch(() => undefined);
  }
}

export async function sendSphinxPacket(
  url: string,
  packet: Uint8Array,
  options?: WebTransportOptions,
): Promise<{ ok: true; text: string; response: Uint8Array }> {
  const stream = await openKatzenpostWebTransport(url, options);
  const writer = stream.writable.getWriter();
  const reader = new StreamByteReader(stream.readable.getReader());
  try {
    await writeFrame(writer, { type: FRAME_SEND_PACKET, status: STATUS_OK, payload: packet });
    const response = await readFrame(reader);
    if (response.type !== FRAME_PACKET_ACK) {
      throw new Error(`unexpected packet ack response type=${response.type}`);
    }
    if (response.status !== STATUS_OK) {
      const text = new TextDecoder().decode(response.payload);
      throw new Error(`gateway rejected packet status=${response.status}${text ? `: ${text}` : ""}`);
    }
    return {
      ok: true,
      response: response.payload,
      text: new TextDecoder().decode(response.payload),
    };
  } finally {
    writer.releaseLock();
    await stream.writable.close().catch(() => undefined);
  }
}

export async function sendSphinxPacketAndWaitReply(
  url: string,
  packet: Uint8Array,
  recipient: Uint8Array,
  options?: WebTransportOptions,
): Promise<Uint8Array> {
  if (recipient.byteLength !== RECIPIENT_ID_LEN) {
    throw new Error(`recipient must be ${RECIPIENT_ID_LEN} bytes`);
  }
  const payload = new Uint8Array(RECIPIENT_ID_LEN + packet.byteLength);
  payload.set(recipient, 0);
  payload.set(packet, RECIPIENT_ID_LEN);

  const stream = await openKatzenpostWebTransport(url, options);
  const writer = stream.writable.getWriter();
  const reader = new StreamByteReader(stream.readable.getReader());
  try {
    await writeFrame(writer, { type: FRAME_SEND_PACKET_WITH_REPLY, status: STATUS_OK, payload });
    const response = await readFrame(reader);
    if (response.type !== FRAME_SURB_REPLY) {
      throw new Error(`unexpected SURB reply response type=${response.type}`);
    }
    if (response.status !== STATUS_OK) {
      const text = new TextDecoder().decode(response.payload);
      throw new Error(`gateway returned SURB reply status=${response.status}${text ? `: ${text}` : ""}`);
    }
    return response.payload;
  } finally {
    writer.releaseLock();
    await stream.writable.close().catch(() => undefined);
  }
}

export async function openOnlineSurbReceiver(
  url: string,
  recipient: Uint8Array,
  options?: WebTransportOptions,
): Promise<OnlineSurbReceiver> {
  if (recipient.byteLength !== RECIPIENT_ID_LEN) {
    throw new Error(`recipient must be ${RECIPIENT_ID_LEN} bytes`);
  }

  const { transport, stream } = await openKatzenpostWebTransportSession(url, options);
  const writer = stream.writable.getWriter();
  const reader = new StreamByteReader(stream.readable.getReader());

  try {
    await writeFrame(writer, { type: FRAME_REGISTER_RECEIVER, status: STATUS_OK, payload: recipient });
  } finally {
    writer.releaseLock();
  }

  const ack = await readFrame(reader);
  if (ack.type !== FRAME_RECEIVER_ACK) {
    transport.close();
    await transport.closed.catch(() => undefined);
    throw new Error(`unexpected receiver ack response type=${ack.type}`);
  }
  if (ack.status !== STATUS_OK) {
    transport.close();
    await transport.closed.catch(() => undefined);
    const text = new TextDecoder().decode(ack.payload);
    throw new Error(`gateway rejected receiver status=${ack.status}${text ? `: ${text}` : ""}`);
  }

  let closed = false;
  return {
    recipient,
    async nextReply(): Promise<Uint8Array> {
      if (closed) {
        throw new Error("online SURB receiver is closed");
      }
      const frame = await readFrame(reader);
      if (frame.type !== FRAME_SURB_REPLY) {
        throw new Error(`unexpected online SURB reply response type=${frame.type}`);
      }
      if (frame.status !== STATUS_OK) {
        const text = new TextDecoder().decode(frame.payload);
        throw new Error(`gateway returned online SURB reply status=${frame.status}${text ? `: ${text}` : ""}`);
      }
      return frame.payload;
    },
    async close(): Promise<void> {
      if (closed) {
        return;
      }
      closed = true;
      await reader.cancel();
      await stream.writable.close().catch(() => undefined);
      transport.close();
      await transport.closed.catch(() => undefined);
    },
  };
}

export async function fetchAndVerifyConsensus(
  url: string,
  epoch: bigint,
  ed25519TrustAnchors: Uint8Array,
  threshold: number,
  maxFutureEpochs = 1n,
  options?: WebTransportOptions,
): Promise<ConsensusCheckStatus & { rawConsensus?: Uint8Array }> {
  const rawConsensus = await fetchConsensus(url, epoch, options);
  const checked = await checkRawConsensus(rawConsensus, ed25519TrustAnchors, threshold, epoch, maxFutureEpochs);
  return { ...checked, rawConsensus };
}

export async function requestConsensusCommand(
  stream: WebTransportBidirectionalStream,
  epoch: bigint,
  paddedLength: number,
): Promise<void> {
  await init();
  const writer = stream.writable.getWriter();
  try {
    await writer.write(encode_get_consensus2(epoch, paddedLength));
  } finally {
    writer.releaseLock();
  }
}

function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.replace(/[\s:]/g, "");
  if (normalized.length % 2 !== 0) {
    throw new Error("hex input has odd length");
  }
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error("hex input contains a non-hex byte");
    }
    out[i] = byte;
  }
  return out;
}

export function mountKatzenpostWtMvp(
  root: HTMLElement,
  defaults: { url?: string; epoch?: bigint; trustAnchorsHex?: string; threshold?: number } = {},
): void {
  root.innerHTML = `
    <form id="kpwt-form">
      <label>WebTransport URL <input name="url" required /></label>
      <label>Epoch <input name="epoch" required inputmode="numeric" /></label>
      <label>Threshold <input name="threshold" required inputmode="numeric" /></label>
      <label>Dirauth Ed25519 keys hex <textarea name="trustAnchors" required rows="6"></textarea></label>
      <button type="submit">Run MVP 1+2</button>
    </form>
    <pre id="kpwt-status">idle</pre>
  `;

  const form = root.querySelector<HTMLFormElement>("#kpwt-form");
  const status = root.querySelector<HTMLPreElement>("#kpwt-status");
  if (!form || !status) {
    throw new Error("failed to mount Katzenpost WT MVP form");
  }

  const urlInput = form.elements.namedItem("url") as HTMLInputElement;
  const epochInput = form.elements.namedItem("epoch") as HTMLInputElement;
  const thresholdInput = form.elements.namedItem("threshold") as HTMLInputElement;
  const trustAnchorsInput = form.elements.namedItem("trustAnchors") as HTMLTextAreaElement;

  urlInput.value = defaults.url ?? "";
  epochInput.value = (defaults.epoch ?? 0n).toString();
  thresholdInput.value = String(defaults.threshold ?? 1);
  trustAnchorsInput.value = defaults.trustAnchorsHex ?? "";

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    status.textContent = "transport: connecting";
    try {
      const url = urlInput.value;
      const epoch = BigInt(epochInput.value);
      const threshold = Number.parseInt(thresholdInput.value, 10);
      const trustAnchors = hexToBytes(trustAnchorsInput.value);

      const proof = await proofOfTransport(url);
      status.textContent = `transport: ${proof.text}\nconsensus: fetching`;

      const checked = await fetchAndVerifyConsensus(url, epoch, trustAnchors, threshold);
      const gateways = checked.consensus?.webtransport_gateways ?? [];
      status.textContent = [
        `transport: ${proof.text}`,
        `consensus: ${checked.state}`,
        checked.error ? `error: ${checked.error}` : "",
        checked.consensus ? `epoch: ${checked.consensus.epoch}` : "",
        checked.consensus ? `signatures: ${checked.consensus.signatures_verified}` : "",
        `webtransport_gateways: ${gateways.length}`,
        ...gateways.map((gateway) => `${gateway.name}: ${gateway.endpoints.join(", ")}`),
      ].filter(Boolean).join("\n");
    } catch (err) {
      status.textContent = `error: ${err instanceof Error ? err.message : String(err)}`;
    }
  });
}
