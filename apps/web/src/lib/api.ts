import type {
  AccessMatrix,
  AuditEvent,
  DeidentificationRow,
  FindingDetail,
  FindingSummary,
  GraphPayload,
  RemediationPayload,
  ReportPayload,
  ScanRun,
  SourceInfo,
  Summary
} from "../types";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function detailToMessage(detail: unknown): string | null {
  if (typeof detail === "string") {
    return detail;
  }
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => (isRecord(item) && typeof item.msg === "string" ? item.msg : null))
      .filter((item): item is string => Boolean(item));
    return messages.length ? messages.join("; ") : null;
  }
  return null;
}

async function responseErrorMessage(path: string, response: Response): Promise<string> {
  const fallback = `${path} failed with ${response.status}`;
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    const payload = (await response.json()) as unknown;
    if (isRecord(payload)) {
      const detail = detailToMessage(payload.detail);
      if (detail) {
        return detail;
      }
      if (typeof payload.message === "string") {
        return payload.message;
      }
    }
    return fallback;
  }
  const text = await response.text();
  const trimmed = text.trim();
  if (trimmed) {
    return trimmed;
  }
  if (response.status >= 500 && path.startsWith("/api")) {
    return `${fallback}. The FastAPI server may be offline or restarting. From the repo root, run npm run dev and keep that terminal open.`;
  }
  return fallback;
}

async function getJson<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, init);
  } catch {
    throw new Error(
      `${path} could not reach the API server. From the repo root, run npm run dev and keep that terminal open.`
    );
  }
  if (!response.ok) {
    throw new Error(await responseErrorMessage(path, response));
  }
  return response.json() as Promise<T>;
}

export const api = {
  summary: () => getJson<Summary>("/api/summary"),
  source: () => getJson<SourceInfo>("/api/source"),
  graph: () => getJson<GraphPayload>("/api/graph"),
  findings: async () => (await getJson<{ items: FindingSummary[] }>("/api/findings")).items,
  finding: (id: string) => getJson<FindingDetail>(`/api/findings/${encodeURIComponent(id)}`),
  deidentification: async () => (await getJson<{ rows: DeidentificationRow[] }>("/api/deidentification")).rows,
  accessMatrix: () => getJson<AccessMatrix>("/api/access-matrix"),
  remediations: () => getJson<RemediationPayload>("/api/remediations"),
  report: () => getJson<ReportPayload>("/api/report"),
  scanRuns: async () => (await getJson<{ items: ScanRun[] }>("/api/scan-runs")).items,
  auditEvents: async () => (await getJson<{ items: AuditEvent[] }>("/api/audit-events")).items,
  resetDemo: () => getJson<SourceInfo>("/api/demo/reset", { method: "POST" }),
  upload: (files: File[], projectName: string) => {
    const formData = new FormData();
    formData.append("project_name", projectName);
    files.forEach((file) => formData.append("files", file));
    return getJson<SourceInfo>("/api/uploads/analyze", {
      method: "POST",
      body: formData
    });
  }
};
