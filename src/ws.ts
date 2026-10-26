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
  private pending = Buffer.alloc(0);
  private fragments: Buffer[] = [];
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
    if (req.headers.upgrade?.toLowerCase() !== "websocket" || typeof key !== "string" || req.headers["sec-websocket-version"] !== "13") {
      socket.write("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
      socket.destroy();
      return undefined;
    }
    const accept = createHash("sha1").update(key + GUID).digest("base64");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    socket.setNoDelay?.(true);
    const ws = new WebSocketConnection(socket);
    if (head.length) ws.feed(head);
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

  private feed(chunk: Buffer): void {
    this.pending = this.pending.length ? Buffer.concat([this.pending, chunk]) : chunk;
    for (;;) {
      const buf = this.pending;
      if (buf.length < 2) return;
      const fin = (buf[0] & 0x80) !== 0;
      const opcode = buf[0] & 0x0f;
      const masked = (buf[1] & 0x80) !== 0;
      let length = buf[1] & 0x7f;
      let offset = 2;
      if (length === 126) {
        if (buf.length < 4) return;
        length = buf.readUInt16BE(2);
        offset = 4;
      } else if (length === 127) {
        if (buf.length < 10) return;
        const big = buf.readBigUInt64BE(2);
        if (big > BigInt(MAX_MESSAGE)) return this.fail("message too large");
        length = Number(big);
        offset = 10;
      }
      if (!masked) return this.fail("client frames must be masked");
      if (buf.length < offset + 4 + length) return;
      const mask = buf.subarray(offset, offset + 4);
      const payload = Buffer.from(buf.subarray(offset + 4, offset + 4 + length));
      for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
      this.pending = buf.subarray(offset + 4 + length);

      switch (opcode) {
        case 0x0: // continuation
          this.fragments.push(payload);
          if (fin) this.deliver(Buffer.concat(this.fragments), this.fragmentText);
          break;
        case 0x1:
        case 0x2:
          if (fin) this.deliver(payload, opcode === 0x1);
          else {
            this.fragments = [payload];
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
    if (data.length > MAX_MESSAGE) return this.fail("message too large");
    this.emit("message", data, isText);
  }

  private fail(reason: string): void {
    this.emit("error", new Error(reason));
    this.closed = true;
    this.socket.destroy();
    this.emit("close", 1002);
  }
}
