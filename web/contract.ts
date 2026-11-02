import { z } from "zod";
export const Scenario = z.strictObject({
  project: z.strictObject({ name: z.string(), title: z.string(), description: z.string() }),
  intro: z.string(),
  steps: z
    .array(
      z.strictObject({
        id: z.string(),
        title: z.string(),
        identity: z.string(),
        action: z.string(),
        data: z.record(z.string(), z.unknown()),
        expect_error: z.number().int().optional(),
      }),
    )
    .min(1)
    .max(30),
});
export function resolve(value: unknown, outputs: Record<string, unknown>, now: string): unknown {
  if (value === "$now") return now;
  if (value === "$future") return new Date(Date.parse(now) + 86400000).toISOString();
  if (value === "$past") return new Date(Date.parse(now) - 172800000).toISOString();
  if (typeof value === "string" && value.startsWith("$")) {
    let result: unknown = outputs;
    for (const part of value.slice(1).split(".")) {
      if (
        ["__proto__", "prototype", "constructor"].includes(part) ||
        result === null ||
        typeof result !== "object" ||
        !Object.hasOwn(result, part)
      )
        throw new Error("Missing prerequisite");
      result = (result as Record<string, unknown>)[part];
    }
    return result;
  }
  if (Array.isArray(value)) return value.map((item) => resolve(item, outputs, now));
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, resolve(item, outputs, now)]),
    );
  return value;
}
