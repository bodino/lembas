// USD per million tokens. Ordered most-specific first, since lookup is by prefix
// ("claude-opus-5" would otherwise swallow "claude-opus-5-5").
// Cache writes are derived from the input price: 1.25x for 5-minute, 2x for 1-hour.
const PRICES: Array<[prefix: string, input: number, output: number, cacheRead: number]> = [
  ["claude-fable-5-1", 10, 50, 0.25],
  ["claude-mythos-5-1", 10, 50, 0.25],
  ["claude-fable-5", 10, 50, 1],
  ["claude-opus-5-5", 4, 20, 0.2],
  ["claude-opus-5", 5, 25, 0.5],
  ["claude-opus-4", 5, 25, 0.5],
  ["claude-sonnet-5-5", 2, 10, 0.2],
  ["claude-sonnet-5", 2, 10, 0.2],
  ["claude-sonnet-4", 3, 15, 0.3],
  ["claude-haiku-5-5", 0.1, 0.5, 0.01],
  ["claude-haiku-4", 1, 5, 0.1],
];

// Unknown models are billed at the most expensive rate so the pool errs on the side of caution.
const FALLBACK = PRICES[0];

export type Usage = {
  input_tokens?: number;
  output_tokens?: number;
  cache_read_input_tokens?: number;
  cache_creation_input_tokens?: number;
  cache_creation?: { ephemeral_5m_input_tokens?: number; ephemeral_1h_input_tokens?: number };
  speed?: string;
};

export function costUsd(model: string | undefined, usage: Usage): number {
  const [, input, output, cacheRead] = PRICES.find(([p]) => model?.startsWith(p)) ?? FALLBACK;

  const write5m = usage.cache_creation?.ephemeral_5m_input_tokens ?? usage.cache_creation_input_tokens ?? 0;
  const write1h = usage.cache_creation?.ephemeral_1h_input_tokens ?? 0;

  const perMillion =
    (usage.input_tokens ?? 0) * input +
    (usage.output_tokens ?? 0) * output +
    (usage.cache_read_input_tokens ?? 0) * cacheRead +
    write5m * input * 1.25 +
    write1h * input * 2;

  const speedMultiplier = usage.speed === "fast" ? 2 : 1;
  return (perMillion / 1_000_000) * speedMultiplier;
}
