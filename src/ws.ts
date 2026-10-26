import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import type { IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";

// A server-side WebSocket (RFC 6455), enough for one bridged byte stream: text and
// binary messages, fragments, ping/pong, close. The pool has no npm dependencies and
// Node ships only the client, so this is written out; it is about a hundred lines.
//
// Events: "message" (data: Buffer, isText: boolean), "close" (code), "error", "drain".

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_MESSAGE = 64 << 20;

export class WebSocketConnection extends EventEmitter {
  // Bytes received and not yet parsed, as they came: joined only when a whole frame is
  // in, so a large frame arriving in small pieces costs linear, not quadratic, copying.
  private pending: Buffer[] = [];
  private pendingBytes = 0;
  private offset = 0; // consumed bytes of pending[0]
  private draining = false;
  private fragments: Buffer[] = [];
  private fragmentBytes = 0;
  private fragmentText = false;
  private closing = false;
  closed = false;
  private readonly socket: Duplex;

  private constructor(socket: Duplex) {
    super();
    this.socket = socket;
    socket.on("data", (chunk: Buffer) => this.feed(chunk));
    socket.on("drain", () => this.emit("drain"));
    socket.on("error", (err) => this.emit("error", err));
    socket.on("close", () => {
      if (this.closed) return;
      this.closed = true;
      this.emit("close", 1006);
    });
  }

  // Answers the upgrade; returns undefined (socket closed) if it isn't a WebSocket request.
  static accept(req: IncomingMessage, socket: Duplex, head: Buffer): WebSocketConnection | undefined {
    const key = req.headers["sec-websocket-key"];
    // The key is 16 random bytes in base64: 22 characters and two pads.
    if (req.headers.upgrade?.toLowerCase() !== "websocket" || typeof key !== "string" || !/^[A-Za-z0-9+/]{22}==$/.test(key) ||
        req.headers["sec-websocket-version"] !== "13") {
      socket.write("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
      socket.destroy();
      return undefined;
    }
    const accept = createHash("sha1").update(key + GUID).digest("base64");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    socket.setNoDelay?.(true);
    const ws = new WebSocketConnection(socket);
    // Bytes that came with the upgrade are parsed once the caller has attached its
    // listeners (it does so right after this returns): a bad first frame must reach
    // its error handler, a good one its message handler.
    // `head` is a view into Node's parser buffer, which it reuses: copy it first.
    if (head.length) {
      const first = Buffer.from(head);
      queueMicrotask(() => ws.feed(first));
    }
    return ws;
  }

  // Returns false when the socket's buffer is full; "drain" follows when it empties.
  send(data: Buffer | string): boolean {
    if (this.closed || this.closing) return true;
    return typeof data === "string" ? this.frame(1, Buffer.from(data)) : this.frame(2, data);
  }

  close(code = 1000, reason = ""): void {
    if (this.closed || this.closing) return;
    this.closing = true;
    const payload = Buffer.alloc(2 + Buffer.byteLength(reason));
    payload.writeUInt16BE(code, 0);
    payload.write(reason, 2);
    this.frame(8, payload);
    // Give the peer a moment to answer with its own close frame, then drop the socket.
    const timer = setTimeout(() => this.socket.destroy(), 2000);
    this.socket.once("close", () => clearTimeout(timer));
  }

  // Drops the connection now, no close handshake: for a peer who is no longer a member.
  terminate(): void {
    if (this.closed) return;
    this.closed = true;
    this.socket.destroy();
    this.emit("close", 1006);
  }

  pause(): void { this.socket.pause(); }
  resume(): void { this.socket.resume(); }

  private frame(opcode: number, payload: Buffer): boolean {
    let header: Buffer;
    if (payload.length < 126) {
      header = Buffer.from([0x80 | opcode, payload.length]);
    } else if (payload.length < 65536) {
      header = Buffer.alloc(4);
      header[0] = 0x80 | opcode;
      header[1] = 126;
      header.writeUInt16BE(payload.length, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x80 | opcode;
      header[1] = 127;
      header.writeBigUInt64BE(BigInt(payload.length), 2);
    }
    return this.socket.write(Buffer.concat([header, payload]));
  }

  // The first `n` pending bytes, without consuming them (fewer if that is all there is).
  private peek(n: number): Buffer {
    const first = this.pending[0].subarray(this.offset);
    if (first.length >= n || this.pending.length === 1) return first.subarray(0, n);
    return Buffer.concat([first, ...this.pending.slice(1)], Math.min(n, this.pendingBytes));
  }

  // Consumes `n` bytes. A frame inside the first chunk is a view with the offset
  // advanced, so a stream of small frames costs linear time; only a frame that spans
  // chunks is copied together.
  private take(n: number): Buffer {
    const first = this.pending[0].subarray(this.offset);
    let out: Buffer;
    if (first.length >= n) {
      out = first.subarray(0, n);
      this.offset += n;
    } else {
      const parts = [first];
      let have = first.length;
      let i = 1;
      while (have < n) {
        parts.push(this.pending[i]);
        have += this.pending[i].length;
        i++;
      }
      out = Buffer.concat(parts, have).subarray(0, n);
      this.pending = this.pending.slice(i - 1);
      this.offset = this.pending[0].length - (have - n);
    }
    this.pendingBytes -= n;
    if (this.offset === this.pending[0].length) {
      this.pending.shift();
      this.offset = 0;
    }
    return out;
  }

  // Frames parsed per turn of the event loop before yielding: a member sending a
  // million tiny frames must not stall every other member's session.
  private static readonly FRAME_BUDGET = 2000;

  private feed(chunk: Buffer): void {
    if (chunk.length) {
      this.pending.push(chunk);
      this.pendingBytes += chunk.length;
    }
    if (this.draining) return; // the scheduled continuation picks the new bytes up
    for (let parsed = 0; ; parsed++) {
      if (parsed >= WebSocketConnection.FRAME_BUDGET) {
        this.draining = true;
        this.socket.pause();
        setImmediate(() => {
          this.draining = false;
          if (this.closed) return;
          this.socket.resume();
          this.feed(Buffer.alloc(0));
        });
        return;
      }
      if (this.pendingBytes < 2) return;
      const head = this.peek(10);
      const fin = (head[0] & 0x80) !== 0;
      const opcode = head[0] & 0x0f;
      const masked = (head[1] & 0x80) !== 0;
      let length = head[1] & 0x7f;
      let offset = 2;
      if (length === 126) {
        if (head.length < 4) return;
        length = head.readUInt16BE(2);
        offset = 4;
      } else if (length === 127) {
        if (head.length < 10) return;
        const big = head.readBigUInt64BE(2);
        if (big > BigInt(MAX_MESSAGE)) return this.fail("message too large");
        length = Number(big);
        offset = 10;
      }
      if (!masked) return this.fail("client frames must be masked");
      // Control frames (close, ping, pong) are short and never fragmented.
      if (opcode >= 0x8 && (length > 125 || !fin)) return this.fail("bad control frame");
      if (this.pendingBytes < offset + 4 + length) return;
      const frame = this.take(offset + 4 + length);
      const mask = frame.subarray(offset, offset + 4);
      const payload = Buffer.from(frame.subarray(offset + 4, offset + 4 + length));
      for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];

      switch (opcode) {
        case 0x0: // continuation
          // Counted as they come, so a stream of never-final fragments cannot
          // grow past the message limit before delivery checks it.
          this.fragmentBytes += payload.length;
          if (this.fragmentBytes > MAX_MESSAGE) return this.fail("message too large");
          this.fragments.push(payload);
          if (fin) this.deliver(Buffer.concat(this.fragments), this.fragmentText);
          break;
        case 0x1:
        case 0x2:
          if (fin) this.deliver(payload, opcode === 0x1);
          else {
            this.fragments = [payload];
            this.fragmentBytes = payload.length;
            this.fragmentText = opcode === 0x1;
          }
          break;
        case 0x8: {
          const code = payload.length >= 2 ? payload.readUInt16BE(0) : 1005;
          if (!this.closing) this.frame(8, payload.subarray(0, 2));
          this.closed = true;
          this.socket.end();
          this.emit("close", code);
          return;
        }
        case 0x9:
          this.frame(0xa, payload);
          break;
        case 0xa:
          break;
        default:
          return this.fail(`unknown opcode ${opcode}`);
      }
    }
  }

  private deliver(data: Buffer, isText: boolean): void {
    this.fragments = [];
    this.fragmentBytes = 0;
    if (data.length > MAX_MESSAGE) return this.fail("message too large");
    this.emit("message", data, isText);
  }

  private fail(reason: string): void {
    if (this.listenerCount("error") > 0) this.emit("error", new Error(reason));
    this.closed = true;
    this.socket.destroy();
    this.emit("close", 1002);
  }
}
