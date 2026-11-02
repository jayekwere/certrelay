import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { resolve, Scenario } from "../web/contract.js";

test("scenario contracts and references retain exact values", () => {
  const raw = JSON.parse(readFileSync("samples/scenario.json", "utf8"));
  const project = JSON.parse(readFileSync("project.json", "utf8"));
  assert.equal(Scenario.parse({ project, ...raw }).steps.length, raw.steps.length);
  assert.deepEqual(
    resolve(
      { at: "$now", values: ["$one.hash", true, null] },
      { one: { hash: "a".repeat(64) } },
      "2026-11-01T12:00:00Z",
    ),
    { at: "2026-11-01T12:00:00Z", values: ["a".repeat(64), true, null] },
  );
  assert.equal(resolve("$past", {}, "2026-11-01T12:00:00Z"), "2026-10-30T12:00:00.000Z");
});
test("reject unknown contract fields, missing references and prototype traversal", () => {
  assert.throws(() => Scenario.parse({ project: {}, steps: [], unexpected: true }));
  for (const value of ["$missing.value", "$__proto__.x", "$constructor", "$one.nope", "$one.x.y"])
    assert.throws(() => resolve(value, { one: { x: null } }, "now"));
});
