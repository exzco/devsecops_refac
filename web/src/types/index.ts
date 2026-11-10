export interface Scan {
  id: number
  repo_url: string
  status: 'pending' | 'running' | 'success' | 'failed'
  error: string
  created_at: string
  updated_at: string
  language: string
  timeout: number
  report_path: string
  commit_sha: string
  worker_id: string
}

export interface Location {
  uri: string
  startLine: number
  startColumn: number
  endLine: number
  endColumn: number
  snippet?: string
}

export interface CodeFlow {
  steps: Array<{
    location: Location
    message: string
  }>
}

export interface Finding {
  rule_id: string
  title: string
  message: string
  level: 'error' | 'warning' | 'note' | 'none'
  security_score: number | null
  cwes: string[]
  locations: Location[]
  related_locations: Location[]
  code_flows: CodeFlow[]
  fingerprints: Record<string, string>
}

export interface WorkerStatus {
  worker_id: string
  online: boolean
  last_seen_at: string | null
}

export interface CreateScanPayload {
  file?: File
  repo_url?: string
  language: string
  timeout: number
}
