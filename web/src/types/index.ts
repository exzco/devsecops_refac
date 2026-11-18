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
  snippetStartLine?: number
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
  hostname?: string
  arch?: string
  pid?: number
  num_cpu?: number
  codeql_path?: string
  codeql_ok?: boolean
  work_root?: string
}

export interface CreateScanPayload {
  file?: File
  repo_url?: string
  language: string
  timeout: number
}

export interface DastEndpoint {
  host: string
  port: number
  transport: 'tcp' | 'udp'
}

export interface DastAssetService {
  endpoint: DastEndpoint
  application_protocol: string
  target_url?: string
  product?: string
  version?: string
  observed_at?: string
}

export interface DastAsset {
  source_id: string
  cmdb_id: string
  cluster_id: string
  host: string
  business_id: string
  owner: string
  network_zone: string
  registered_services: DastAssetService[]
}

export interface DastAssetFilter {
  source_id?: string
  cluster_id?: string
  network_zone?: string
  business_id?: string
}

export interface DastPortSpec {
  port: number
  transport: 'tcp' | 'udp'
}

export interface DastScanOptions {
  template_version: string
  template_ids: string[]
  rate_limit: number
  concurrency: number
  timeout_seconds: number
  probe_ports: DastPortSpec[]
}

export interface DastCreateScanRequest {
  request_key: string
  assets: Array<{ source_id: string; cmdb_id: string }>
  filter: DastAssetFilter
  options: DastScanOptions
}

export interface DastScan {
  hosts?: { id: string; host: string; status: DastTask['status'] }[]
  id: string
  created_by: string
  total_tasks: number
  finished_tasks: number
  failed_tasks: number
  status: 'pending' | 'running' | 'success' | 'failed' | 'cancelled'
  created_at: string
  started_at?: string
  finished_at?: string
}

export interface DastTask {
  id: string
  scan_id: string
  plan: {
    asset: DastAsset
    options: DastScanOptions
  }
  status: 'pending' | 'running' | 'success' | 'failed' | 'cancelled'
  worker_id: string
  execution_deadline?: string
  created_at: string
  started_at?: string
  finished_at?: string
  error?: string
}

export interface DastPortObservation {
  endpoint: DastEndpoint
  state: string
  reason?: string
  observed_at: string
}

export interface DastCoverageIssue {
  endpoint: DastEndpoint
  template_id?: string
  reason: string
}

export interface DastFinding {
  id?: string
  scan_id?: string
  task_id?: string
  matcher_name: string
  template_id: string
  title: string
  description: string
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical' | 'unknown'
  endpoint: DastEndpoint
  target_url?: string
  matched_at: string
  cwes: string[]
  cves: string[]
  references: string[]
  evidence?: {
    request?: string
    response?: string
    extracted_values?: string[]
  }
}

export interface DastTaskResult {
  resolved_ips: string[]
  ports: DastPortObservation[]
  coverage: DastCoverageIssue[]
  services: DastAssetService[]
  findings: DastFinding[]
  executed_checks: number | null
  failed_checks: number | null
}

export interface DastTaskDetail {
  task: DastTask
  result: DastTaskResult | null
  unregistered: DastAssetService[]
}

export interface DastScanDetail {
  scan: DastScan
  tasks: DastTask[]
}

export interface DastWorkerStatus {
  instance_id: string
  cluster_id: string
  network_zone: string
  template_version: string
  last_seen_at: string
  online: boolean
}
