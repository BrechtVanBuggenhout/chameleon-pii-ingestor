import http from "k6/http";
import { check, sleep } from "k6";
import { Trend, Rate } from "k6/metrics";
import exec from "k6/execution";

const vaultUrl = __ENV.VAULT_URL || "http://localhost:8080";
const tenantId = __ENV.TENANT_ID || "k6-tenant-a";
const totalUsers = Number(__ENV.TOTAL_USERS || 10000);
const batchSize = Number(__ENV.BATCH_SIZE || 1000);
const batchIterations = Math.ceil(totalUsers / batchSize);
const requestedPhase = __ENV.PHASE || "all";
const phase = ["all", "batch", "generate", "context", "lineage"].includes(requestedPhase)
  ? requestedPhase
  : "all";
const generationMaxDuration = __ENV.GENERATION_MAX_DURATION || "2m";
const contextStart = __ENV.CONTEXT_START || "2m10s";

const batchGenerateLatency = new Trend("batch_generate_latency");
const batchContextLatency = new Trend("batch_context_latency");
const lineageLatency = new Trend("lineage_latency");
const kvErrors = new Rate("key_vault_errors");

function scenarios() {
  const batchKeyGeneration = {
    executor: "shared-iterations",
    vus: Number(__ENV.BATCH_VUS || 10),
    iterations: batchIterations,
    exec: "batchGenerate",
    startTime: "0s",
    maxDuration: generationMaxDuration,
  };
  const batchEncryptionContext = {
    executor: "shared-iterations",
    vus: Number(__ENV.BATCH_VUS || 10),
    iterations: batchIterations,
    exec: "batchEncryptionContext",
    startTime: phase === "context" ? "0s" : contextStart,
  };
  const lineageEvents = {
    executor: "constant-arrival-rate",
    rate: Number(__ENV.LINEAGE_RPS || 250),
    timeUnit: "1s",
    duration: __ENV.LINEAGE_DURATION || "1m",
    preAllocatedVUs: Number(__ENV.LINEAGE_VUS || 50),
    maxVUs: Number(__ENV.LINEAGE_MAX_VUS || 200),
    exec: "lineageEvent",
    startTime: phase === "lineage" ? "0s" : __ENV.LINEAGE_START || "40s",
  };

  if (phase === "generate") {
    return { batch_key_generation: batchKeyGeneration };
  }
  if (phase === "context") {
    return { batch_encryption_context: batchEncryptionContext };
  }
  if (phase === "lineage") {
    return { lineage_events: lineageEvents };
  }
  if (phase === "batch") {
    return {
      batch_key_generation: batchKeyGeneration,
      batch_encryption_context: batchEncryptionContext,
    };
  }

  return {
    batch_key_generation: batchKeyGeneration,
    batch_encryption_context: batchEncryptionContext,
    lineage_events: lineageEvents,
  };
}

function thresholds() {
  const activeThresholds = {
    http_req_failed: ["rate<0.01"],
    key_vault_errors: ["rate<0.01"],
  };

  if (phase === "generate" || phase === "batch" || phase === "all") {
    activeThresholds.batch_generate_latency = ["p(95)<2000", "p(99)<5000"];
  }
  if (phase === "context" || phase === "batch" || phase === "all") {
    activeThresholds.batch_context_latency = ["p(95)<2500", "p(99)<6000"];
  }
  if (phase === "lineage" || phase === "all") {
    activeThresholds.lineage_latency = ["p(95)<750", "p(99)<1500"];
  }

  return activeThresholds;
}

export const options = {
  scenarios: scenarios(),
  thresholds: thresholds(),
};

function headers() {
  return {
    "Content-Type": "application/json",
    "X-Tenant-Id": tenantId,
  };
}

function batchUserIds(iteration) {
  const start = iteration * batchSize;
  const end = Math.min(start + batchSize, totalUsers);
  const ids = [];
  for (let i = start; i < end; i += 1) {
    ids.push(`k6-user-${i}`);
  }
  return ids;
}

export function batchGenerate() {
  const payload = JSON.stringify({
    tenantId,
    userIds: batchUserIds(exec.scenario.iterationInTest),
  });
  const res = http.post(`${vaultUrl}/keys/batch-generate`, payload, { headers: headers() });
  batchGenerateLatency.add(res.timings.duration);
  kvErrors.add(res.status >= 400);
  check(res, {
    "batch generate accepted": (r) => r.status >= 200 && r.status < 300,
  });
  sleep(0.1);
}

export function batchEncryptionContext() {
  const payload = JSON.stringify({
    tenantId,
    userIds: batchUserIds(exec.scenario.iterationInTest),
  });
  const res = http.post(`${vaultUrl}/keys/batch-encryption-context`, payload, { headers: headers() });
  batchContextLatency.add(res.timings.duration);
  kvErrors.add(res.status >= 400);
  check(res, {
    "batch context accepted": (r) => r.status >= 200 && r.status < 300,
  });
  sleep(0.1);
}

export function lineageEvent() {
  const userId = `k6-user-${__ITER % totalUsers}`;
  const payload = JSON.stringify({
    event_type: "DATA_PROVISIONED_TO_SINK",
    eventType: "DATA_PROVISIONED_TO_SINK",
    tenant_id: tenantId,
    user_id: userId,
    userId,
    source: "pii-ingestion-worker",
    destination: "bigquery.stg_users",
    data_classification: "PII",
    dataClassification: "PII",
    operation_id: `k6-op-${__VU}`,
    operationId: `k6-op-${__VU}`,
    metadata: {
      runner: "k6",
      scenario: "lineage_events",
    },
  });
  const res = http.post(`${vaultUrl}/lineage/events`, payload, { headers: headers() });
  lineageLatency.add(res.timings.duration);
  kvErrors.add(res.status >= 400);
  check(res, {
    "lineage accepted": (r) => r.status >= 200 && r.status < 300,
  });
}
