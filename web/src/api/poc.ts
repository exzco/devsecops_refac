import { http } from './index'
export interface Link { url: string; title: string }
export interface Manual { title: string; description: string; pocs: Link[]; notes: string }
export interface CVE { id: string; sources: Record<string, any>; discovered: Link[]; manual: Partial<Manual>; searched_at: string | null; updated_at: string }
export interface Job { id: number; kind: string; status: string; progress: string; error: string }
export interface Evidence { source: string; text: string }
export interface Product { key: string; name: string; fingerprints: string; version_endpoints: string; evidence: Evidence[] }
export type PoCKind = 'fingerprint' | 'vulnerability' | 'legacy'
export interface PoCResult { kind: PoCKind; status: 'draft' | 'needs-evidence'; reason: string; missing_information: string[]; template: Record<string, unknown> | null }
export interface Spec { version: 1 | 2; product_key: string; name: string; results: PoCResult[]; evidence: Evidence[] }
export interface Generation { id: number; cve_id: string; spec: Spec; templates: Partial<Record<PoCKind, string>>; created_at: string }
export interface GenerationContext { cve: CVE; description: string; products: Product[]; materials: Evidence[]; notices: string[] }
export interface AgentSettings { protocol: string; base_url: string; model: string; has_api_key: boolean; configuration_error: string; schema: unknown }
export interface CatalogParams {
  q?: string
  filter?: string
  year?: string
  start?: string
  end?: string
  limit?: number
}
export async function loadCatalog(params?: CatalogParams): Promise<CVE[]> {
  const res = await http.get<CVE[]>('/dast/pocs', { params })
  return res.data
}
export function description(c: CVE): string {
  if (c.manual.description) return c.manual.description
  if (c.sources['CVEProject/cvelistV5']?.description) return c.sources['CVEProject/cvelistV5'].description
  const nvd = c.sources.nvd
  const english = nvd?.descriptions?.find((d: { lang: string }) => d.lang === 'en')
  if (english) return english.value
  const advisory = Object.values(c.sources).find(s => s.description)
  return advisory?.description ?? ''
}
export const poc = {
  save: async (id: string, manual: Manual) => { await http.put(`/dast/pocs/${encodeURIComponent(id)}`, manual) },
  sync: (start: string, end: string) => http.post('/dast/pocs/sync', { start, end }),
  search: (ids: string[]) => http.post('/dast/pocs/search', { ids }),
  jobs: () => http.get<Job[]>('/dast/poc-jobs').then(r => r.data),
  products: () => http.get<Product[]>('/dast/poc-products').then(r => r.data),
  saveProduct: (p: Product) => http.put(`/dast/poc-products/${encodeURIComponent(p.key)}`, p),
  agent: () => http.get<AgentSettings>('/dast/poc-agent').then(r => r.data),
  context: (id: string) => http.get<GenerationContext>(`/dast/poc-context/${encodeURIComponent(id)}`, { timeout: 35000 }).then(r => r.data),
  refreshContext: (id: string) => http.post<GenerationContext>(`/dast/poc-context/${encodeURIComponent(id)}/refresh`, {}, { timeout: 35000 }).then(r => r.data),
  saveAgent: (settings: { protocol: string; base_url: string; model: string; api_key: string }) => http.put<AgentSettings>('/dast/poc-agent', settings).then(r => r.data),
  generate: (ids: string[]) => http.post<number[]>('/dast/poc-generate', { ids }),
  generations: () => http.get<Generation[]>('/dast/poc-generations').then(r => r.data),
  saveSpec: (id: number, spec: Spec) => http.put(`/dast/poc-generations/${id}`, spec),
}
