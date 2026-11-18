// The engine's session protocol (see apps/stackrabbit/src/protocol.rs): a
// frame is two little-endian 32-bit lengths (header, payload), a JSON
// header and a payload. No `vscode` dependency, so it is tested under Node.
"use strict";

const MAX_HEADER = 16 << 20;
const MAX_PAYLOAD = 1 << 30;

/** A frame's bytes: `header` (an object) and `payload` (a Buffer, or none). */
function encode(header, payload) {
  const h = Buffer.from(JSON.stringify(header), "utf8");
  const p = payload || Buffer.alloc(0);
  if (h.length > MAX_HEADER || p.length > MAX_PAYLOAD) {
    throw new Error("frame too large");
  }
  const prefix = Buffer.alloc(8);
  prefix.writeUInt32LE(h.length, 0);
  prefix.writeUInt32LE(p.length, 4);
  return Buffer.concat([prefix, h, p]);
}

/**
 * Reads frames from chunks as they arrive: `push(chunk)` returns the
 * frames completed, `{ header, payload }` each. A malformed frame throws.
 */
class Decoder {
  constructor() {
    this.chunks = [];
    this.length = 0;
  }

  push(chunk) {
    this.chunks.push(chunk);
    this.length += chunk.length;
    const frames = [];
    for (;;) {
      if (this.length < 8) {
        break;
      }
      const prefix = this.peek(8);
      const headerLength = prefix.readUInt32LE(0);
      const payloadLength = prefix.readUInt32LE(4);
      if (headerLength > MAX_HEADER || payloadLength > MAX_PAYLOAD) {
        throw new Error("a frame's lengths are out of range");
      }
      const total = 8 + headerLength + payloadLength;
      if (this.length < total) {
        break;
      }
      const frame = this.take(total);
      const header = JSON.parse(frame.subarray(8, 8 + headerLength).toString("utf8"));
      if (header === null || typeof header !== "object" || Array.isArray(header)) {
        throw new Error("a frame's header isn't a JSON object");
      }
      frames.push({ header, payload: frame.subarray(8 + headerLength) });
    }
    return frames;
  }

  /** The first `n` buffered bytes, without consuming them. */
  peek(n) {
    if (this.chunks[0].length >= n) {
      return this.chunks[0].subarray(0, n);
    }
    const all = Buffer.concat(this.chunks);
    this.chunks = [all];
    return all.subarray(0, n);
  }

  /** The first `n` buffered bytes, consumed. */
  take(n) {
    const all = this.chunks.length === 1 ? this.chunks[0] : Buffer.concat(this.chunks);
    const out = all.subarray(0, n);
    const rest = all.subarray(n);
    this.chunks = rest.length ? [rest] : [];
    this.length -= n;
    return out;
  }
}

/**
 * A session with an engine: `request(method, params)` sends a request and
 * resolves with its result (or rejects with its error). `write(bytes)` is
 * how frames go out; feed what comes back to `receive(chunk)`.
 */
class Session {
  /** `onNotification(method, params)` hears what the engine says unasked. */
  constructor(write, onNotification) {
    this.write = write;
    this.onNotification = onNotification || (() => {});
    this.decoder = new Decoder();
    this.next = 1;
    this.pending = new Map();
  }

  request(method, params) {
    const id = this.next++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, method });
      try {
        this.write(encode({ id, method, params: params || {} }));
      } catch (e) {
        this.pending.delete(id);
        reject(e);
      }
    });
  }

  receive(chunk) {
    for (const { header } of this.decoder.push(chunk)) {
      if (header.id === undefined && typeof header.method === "string") {
        this.onNotification(header.method, header.params || {});
        continue;
      }
      const waiter = this.pending.get(header.id);
      if (!waiter) {
        continue;
      }
      this.pending.delete(header.id);
      if (header.error !== undefined) {
        waiter.reject(new Error(String(header.error)));
      } else {
        waiter.resolve(header.result);
      }
    }
  }

  /** Fails every request still waiting (the engine went away). */
  close(reason) {
    for (const [, waiter] of this.pending) {
      waiter.reject(new Error(reason));
    }
    this.pending.clear();
  }
}

module.exports = { encode, Decoder, Session, MAX_HEADER, MAX_PAYLOAD };
