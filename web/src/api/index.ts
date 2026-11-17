import axios from 'axios'
import type {
  Scan,
  Finding,
  Location,
  WorkerStatus,
  CreateScanPayload,
  DastAsset,
  DastAssetFilter,
  DastCreateScanRequest,
  DastFinding,
  DastScan,
  DastScanDetail,
  DastTaskDetail,
  DastWorkerStatus,
} from '@/types'

export const http = axios.create({ baseURL: '/api/v1', timeout: 30_000 })

// DAST 的接口按调用方隔离数据，请求必须带上身份；接入统一登录后改为读取令牌。
const DAST_USER_ID = 'web-console'

http.interceptors.request.use((config) => {
  config.headers.set('X-User-Id', DAST_USER_ID)
  return config
})

http.interceptors.response.use(
  (r) => r,
  (e) => Promise.reject(new Error(e.response?.data?.error ?? e.message)),
)

// Keep the UI model consistent while accepting the Go model's original JSON field names.
type ScanResponse = Partial<Scan> & {
  ID?: number
  RepoURL?: string
  Status?: Scan['status']
  Error?: string
  CreatedAt?: string
  UpdatedAt?: string
  Language?: string
  Timeout?: number
  ReportPath?: string
  CommitSHA?: string
  WorkerID?: string
}

function normalizeScan(raw: ScanResponse): Scan {
  const id = raw.id ?? raw.ID
  const status = raw.status ?? raw.Status
  if (id == null || status == null) throw new Error('扫描接口响应缺少任务 ID 或状态')
  return {
    id,
    status,
    repo_url: raw.repo_url ?? raw.RepoURL ?? '',
    error: raw.error ?? raw.Error ?? '',
    created_at: raw.created_at ?? raw.CreatedAt ?? '',
    updated_at: raw.updated_at ?? raw.UpdatedAt ?? '',
    language: raw.language ?? raw.Language ?? '',
    timeout: raw.timeout ?? raw.Timeout ?? 0,
    report_path: raw.report_path ?? raw.ReportPath ?? '',
    commit_sha: raw.commit_sha ?? raw.CommitSHA ?? '',
    worker_id: raw.worker_id ?? raw.WorkerID ?? '',
  }
}

function normalizeLocation(raw: any): Location {
  if (!raw) {
    return { uri: '', startLine: 0, startColumn: 0, endLine: 0, endColumn: 0, snippet: '' }
  }
  return {
    uri: raw.uri ?? raw.file ?? '',
    startLine: raw.startLine ?? raw.start_line ?? 0,
    startColumn: raw.startColumn ?? raw.start_column ?? 0,
    endLine: raw.endLine ?? raw.end_line ?? 0,
    endColumn: raw.endColumn ?? raw.end_column ?? 0,
    snippet: raw.snippet ?? '',
    snippetStartLine: raw.snippetStartLine ?? raw.snippet_start_line ?? raw.startLine ?? raw.start_line ?? 0,
  }
}

function normalizeFinding(raw: any): Finding {
  const codeFlows = (raw.code_flows ?? []).map((cf: any) => {
    let steps: any[] = []
    if (Array.isArray(cf.steps) && cf.steps.length > 0) {
      steps = cf.steps
    } else if (Array.isArray(cf.thread_flows) && cf.thread_flows.length > 0) {
      steps = cf.thread_flows[0]?.steps ?? []
    }
    return {
      steps: steps.map((s: any) => ({
        location: normalizeLocation(s.location),
        message: s.message ?? s.location?.message ?? '',
      })),
    }
  })

  return {
    rule_id: raw.rule_id ?? raw.ruleId ?? '',
    title: raw.title ?? '',
    message: raw.message ?? '',
    level: raw.level ?? 'warning',
    security_score: raw.security_score ?? raw.securityScore ?? null,
    cwes: raw.cwes ?? [],
    locations: (raw.locations ?? []).map(normalizeLocation),
    related_locations: (raw.related_locations ?? raw.relatedLocations ?? []).map(normalizeLocation),
    code_flows: codeFlows,
    fingerprints: raw.fingerprints ?? {},
  }
}

export const api = {
  listScans: () => http.get<ScanResponse[]>('/scans').then((r) => r.data.map(normalizeScan)),
  getScan: (id: number) => http.get<ScanResponse>(`/scans/${id}`).then((r) => normalizeScan(r.data)),
  deleteScan: (id: number) => http.delete(`/scans/${id}`),
  createScan: (payload: CreateScanPayload) => {
    if (payload.file) {
      const fd = new FormData()
      fd.append('file', payload.file)
      fd.append('language', payload.language)
      fd.append('timeout', String(payload.timeout))
      return http.post<ScanResponse>('/scans', fd).then((r) => normalizeScan(r.data))
    }
    return http.post<ScanResponse>('/scans', payload).then((r) => normalizeScan(r.data))
  },
  getScanFindings: (id: number) =>
    http.get<any[]>(`/scans/${id}/findings`).then((r) => r.data.map(normalizeFinding)),
  listWorkers: () => http.get<WorkerStatus[]>('/workers').then((r) => r.data),

  // DAST
  listDastAssets: (filter: DastAssetFilter = {}) =>
    http.get<DastAsset[]>('/dast/assets', { params: filter }).then((r) => r.data),
  createDastAsset: (asset: DastAsset) =>
    http.post<DastAsset>('/dast/assets', asset).then((r) => r.data),
  createDastScan: (payload: DastCreateScanRequest) =>
    http.post<DastScan>('/dast/scans', payload).then((r) => r.data),
  listDastScans: () => http.get<DastScan[]>('/dast/scans').then((r) => r.data),
  getDastScan: (id: string | number) =>
    http.get<DastScanDetail>(`/dast/scans/${id}`).then((r) => r.data),
  getDastTask: (id: string | number) =>
    http.get<DastTaskDetail>(`/dast/tasks/${id}`).then((r) => r.data),
  getDastScanFindings: (id: string | number) =>
    http.get<DastFinding[]>(`/dast/scans/${id}/findings`).then((r) => r.data),
  listDastWorkers: () => http.get<DastWorkerStatus[]>('/dast/workers').then((r) => r.data),
}
