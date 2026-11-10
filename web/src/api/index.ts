import axios from 'axios'
import type { Scan, Finding, WorkerStatus, CreateScanPayload } from '@/types'

const http = axios.create({ baseURL: '/api/v1', timeout: 10_000 })

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

export const api = {
  listScans: () => http.get<ScanResponse[]>('/scans').then((r) => r.data.map(normalizeScan)),
  getScan: (id: number) => http.get<ScanResponse>(`/scans/${id}`).then((r) => normalizeScan(r.data)),
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
    http.get<Finding[]>(`/scans/${id}/findings`).then((r) => r.data),
  listWorkers: () => http.get<WorkerStatus[]>('/workers').then((r) => r.data),
}
