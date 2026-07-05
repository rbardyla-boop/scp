type RelayStatus = "live" | "down" | "restored";

interface TraceRelay {
  id: string;
  label: string;
  role: string;
}

interface TickRelay {
  id: string;
  status: RelayStatus;
  stored_bursts: number;
}

interface TraceTick {
  tick: number;
  time_label: string;
  phase: string;
  relay_count: number;
  live_relay_count: number;
  delivery_success_count: number;
  delivery_failure_count: number;
  selection_entropy_bits: number;
  kappa: number;
  exposure_estimate: number;
  membership_confidence: number;
  relays: TickRelay[];
  events: string[];
}

interface ReplayTrace {
  run_id: string;
  scenario: string;
  honesty_label: string;
  relays: TraceRelay[];
  ticks: TraceTick[];
}

const TRACE_URL = "./relay-kill-failover-live-2026-07-05.trace.json";
const TICK_MS = 1600;

let trace: ReplayTrace | null = null;
let currentTick = 0;
let playTimer: number | undefined;

function byId<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error(`missing element: ${id}`);
  }
  return element as T;
}

function formatUnit(value: number): string {
  return value.toFixed(2);
}

function setText(id: string, value: string): void {
  byId(id).textContent = value;
}

function relayMeta(id: string): TraceRelay | undefined {
  return trace?.relays.find((relay) => relay.id === id);
}

function renderRelays(tick: TraceTick): void {
  const strip = byId("relay-strip");
  strip.replaceChildren();

  for (const relay of tick.relays) {
    const meta = relayMeta(relay.id);
    const item = document.createElement("div");
    item.className = "relay-node";
    item.dataset.status = relay.status;

    const label = document.createElement("strong");
    label.textContent = meta?.label ?? relay.id;

    const status = document.createElement("span");
    status.textContent = relay.status;

    const details = document.createElement("p");
    details.textContent = `${meta?.role ?? "configured"}; stored bursts: ${
      relay.stored_bursts
    }`;

    item.append(label, status, details);
    strip.append(item);
  }
}

function renderEvents(tick: TraceTick): void {
  const log = byId("event-log");
  log.replaceChildren();

  for (const eventText of tick.events) {
    const item = document.createElement("li");
    item.textContent = eventText;
    log.append(item);
  }
}

function renderTick(index: number): void {
  if (!trace) return;

  const clamped = Math.max(0, Math.min(index, trace.ticks.length - 1));
  const tick = trace.ticks[clamped];
  currentTick = clamped;

  const exposure = Math.max(0, Math.min(tick.exposure_estimate, 1));
  const angle = -90 + exposure * 180;
  const meter = byId("exposure-meter");
  const needle = byId("meter-needle");
  const scrubber = byId<HTMLInputElement>("trace-scrubber");

  meter.setAttribute("aria-valuenow", String(Math.round(exposure * 100)));
  needle.style.setProperty("--needle-angle", `${angle.toFixed(1)}deg`);
  scrubber.value = String(clamped);

  setText("exposure-value", formatUnit(tick.exposure_estimate));
  setText("metric-kappa", formatUnit(tick.kappa));
  setText("metric-entropy", `${formatUnit(tick.selection_entropy_bits)} bits`);
  setText("metric-confidence", formatUnit(tick.membership_confidence));
  setText("metric-live-relays", `${tick.live_relay_count} / ${tick.relay_count}`);
  setText("phase-label", tick.phase);
  setText("time-label", tick.time_label);

  renderRelays(tick);
  renderEvents(tick);
}

function stopReplay(): void {
  if (playTimer !== undefined) {
    window.clearInterval(playTimer);
    playTimer = undefined;
  }
  setText("play-toggle", "Play");
}

function startReplay(): void {
  if (!trace || playTimer !== undefined) return;

  setText("play-toggle", "Pause");
  playTimer = window.setInterval(() => {
    if (!trace) return;
    if (currentTick >= trace.ticks.length - 1) {
      stopReplay();
      return;
    }
    renderTick(currentTick + 1);
  }, TICK_MS);
}

function bindControls(): void {
  const play = byId<HTMLButtonElement>("play-toggle");
  const reset = byId<HTMLButtonElement>("reset-trace");
  const scrubber = byId<HTMLInputElement>("trace-scrubber");

  play.addEventListener("click", () => {
    if (playTimer === undefined) {
      startReplay();
    } else {
      stopReplay();
    }
  });

  reset.addEventListener("click", () => {
    stopReplay();
    renderTick(0);
  });

  scrubber.addEventListener("input", () => {
    stopReplay();
    renderTick(Number(scrubber.value));
  });
}

async function loadTrace(): Promise<void> {
  const response = await fetch(TRACE_URL);
  if (!response.ok) {
    throw new Error(`trace fetch failed: ${response.status}`);
  }

  trace = (await response.json()) as ReplayTrace;
  const scrubber = byId<HTMLInputElement>("trace-scrubber");
  scrubber.max = String(Math.max(trace.ticks.length - 1, 0));
  setText("honesty-label", trace.honesty_label);
  renderTick(0);
}

document.addEventListener("DOMContentLoaded", () => {
  bindControls();
  loadTrace().catch((error: unknown) => {
    stopReplay();
    setText("phase-label", "Trace unavailable");
    const log = byId("event-log");
    const item = document.createElement("li");
    item.textContent =
      error instanceof Error ? error.message : "Unknown trace loading error";
    log.replaceChildren(item);
  });
});
