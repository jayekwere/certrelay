import { resolve, Scenario } from "./contract.js";

const el = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const show = (value: unknown) => JSON.stringify(value, null, 2);
const session = crypto.randomUUID().replaceAll("-", "");
let scenario: ReturnType<typeof Scenario.parse>;
let current = 0;
const outputs: Record<string, unknown> = {};
const completed = new Set<number>();
const identity = el<HTMLSelectElement>("identity");
const run = el<HTMLButtonElement>("run");
function decision(message: string, denied = false) {
  el("decision").textContent = message;
  el("decision").className = denied ? "denied" : "";
}
function select(index: number) {
  current = index;
  const step = scenario.steps[index];
  if (!step) return;
  el("step-title").textContent = step.title;
  identity.value = step.identity;
  el("actor-badge").textContent =
    `${step.identity.replace("demo-", "")} · ${step.expect_error ? "expected denial" : "expected success"}`;
  let data: unknown;
  try {
    data = resolve(step.data, outputs, new Date().toISOString());
  } catch {
    data = { prerequisite: "Run earlier steps to obtain their exact evidence references." };
  }
  el("request").textContent = show({ action: step.action, data });
  document.querySelectorAll(".step").forEach((node, i) => {
    node.classList.toggle("active", index === i);
    node.classList.toggle("done", completed.has(i));
  });
}
async function request(url: string, body?: unknown) {
  const response = await fetch(url, {
    method: body ? "POST" : "GET",
    headers: {
      Authorization: `Bearer ${identity.value}`,
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    ...(body ? { body: show(body) } : {}),
  });
  const result: unknown = await response.json();
  return { response, result };
}
run.addEventListener("click", async () => {
  run.disabled = true;
  try {
    const step = scenario.steps[current];
    if (!step) return;
    const data = resolve(step.data, outputs, new Date().toISOString());
    const { response, result } = await request("/api/actions", {
      action: step.action,
      data,
      key: `web-${session}-${current}`,
    });
    el("output").textContent = show(result);
    const expected = step.expect_error ?? 200;
    if (response.status !== expected) {
      decision(`Unexpected result: HTTP ${response.status}`, true);
      return;
    }
    if (response.ok) {
      const parsed = result as { result: unknown; checkpoint: string };
      outputs[step.id] = parsed.result;
      el("receipt").textContent = `Receipt ${parsed.checkpoint.slice(0, 16)}`;
    }
    completed.add(current);
    el("progress").textContent = `${completed.size} / ${scenario.steps.length} completed`;
    decision(
      response.ok ? "Operation verified" : `Expected denial verified · HTTP ${response.status}`,
      !response.ok,
    );
    const fact = document.createElement("span");
    fact.className = "fact";
    fact.textContent = `${current + 1}. ${response.ok ? "Recorded" : "Denied as expected"}`;
    el("facts").append(fact);
    select(Math.min(current + 1, scenario.steps.length - 1));
  } catch {
    decision("Request unavailable or a prerequisite step is missing", true);
  } finally {
    run.disabled = false;
  }
});
for (const [id, url] of [
  ["state", "/api/state"],
  ["evidence", "/api/evidence"],
]) {
  el(id!).addEventListener("click", async () => {
    try {
      if (id === "evidence") identity.value = "demo-reviewer";
      const { response, result } = await request(url!);
      el("output").textContent = show(result);
      el("step-title").textContent =
        id === "evidence" ? "Tenant audit evidence" : "Scoped domain state";
      el("actor-badge").textContent = identity.value.replace("demo-", "");
      decision(
        response.ok
          ? id === "evidence"
            ? "Audit chain verified"
            : "Current scoped state"
          : "Access denied",
        !response.ok,
      );
    } catch {
      decision("Local service unavailable", true);
    }
  });
}
async function start() {
  const response = await fetch("/api/scenario");
  if (!response.ok) throw new Error("Scenario unavailable");
  scenario = Scenario.parse(await response.json());
  el("title").textContent = scenario.project.title;
  document.title = `${scenario.project.title} | Security workbench`;
  el("intro").textContent = scenario.intro;
  identity.replaceChildren(
    ...["operator", "reviewer", "auditor", "clinician", "support", "privacy", "other"].map(
      (role) => {
        const option = document.createElement("option");
        option.value = `demo-${role}`;
        option.textContent =
          role === "other" ? "Other tenant" : `${role[0]?.toUpperCase()}${role.slice(1)}`;
        return option;
      },
    ),
  );
  scenario.steps.forEach((step, index) => {
    const button = document.createElement("button");
    button.className = "step";
    const number = document.createElement("span");
    number.className = "number";
    number.textContent = String(index + 1);
    const text = document.createElement("span");
    const title = document.createElement("strong");
    title.textContent = step.title;
    const actor = document.createElement("small");
    actor.textContent = `${step.identity.replace("demo-", "")} · ${step.expect_error ? "negative control" : "operation"}`;
    text.append(title, actor);
    button.append(number, text);
    button.addEventListener("click", () => select(index));
    el("steps").append(button);
  });
  select(0);
  run.disabled = false;
}
start().catch(() => {
  decision("Start the local demo service to use this workbench", true);
});
