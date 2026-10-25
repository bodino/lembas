import type { Usage } from "./pricing.ts";

// Watches response bytes as they stream through to the client and pulls out token usage.
// Streaming responses report usage in `message_start` (input side) and `message_delta`
// (cumulative output); plain JSON responses carry it in the top-level `usage` field.
export class UsageTap {
  usage: Usage = {};
  private buffer = "";
  private decoder = new TextDecoder();
  private isSse: boolean;

  constructor(contentType: string | null) {
    this.isSse = (contentType ?? "").includes("text/event-stream");
  }

  push(chunk: Uint8Array): void {
    this.buffer += this.decoder.decode(chunk, { stream: true });
    if (!this.isSse) return;

    const lines = this.buffer.split("\n");
    this.buffer = lines.pop() ?? "";
    for (const line of lines) {
      if (!line.startsWith("data:")) continue;
      try {
        const event = JSON.parse(line.slice(5));
        if (event.type === "message_start") this.merge(event.message?.usage);
        else if (event.type === "message_delta") this.merge(event.usage);
      } catch {
        // Not JSON (e.g. a ping) - ignore.
      }
    }
  }

  finish(): Usage {
    if (!this.isSse) {
      try {
        this.merge(JSON.parse(this.buffer).usage);
      } catch {
        // Non-JSON body (or one without usage, like count_tokens) - costs nothing.
      }
    }
    return this.usage;
  }

  private merge(partial: Record<string, unknown> | undefined): void {
    if (!partial) return;
    for (const [key, value] of Object.entries(partial)) {
      if (value !== null && value !== undefined) (this.usage as Record<string, unknown>)[key] = value;
    }
  }
}
