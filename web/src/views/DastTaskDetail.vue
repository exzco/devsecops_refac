<template>
  <div class="h-full flex flex-col overflow-hidden gap-3">
    <!-- 顶部紧凑信息条（固定无滚动） -->
    <div class="bg-white rounded-xl border border-slate-200/80 px-4 py-2.5 shadow-2xs flex items-center justify-between shrink-0">
      <div class="flex items-center gap-3">
        <a-button size="small" @click="router.push('/dast/tasks')">
          <template #icon><ArrowLeft class="w-3.5 h-3.5 inline-block mr-1" /></template>
          返回批次列表
        </a-button>
        <div class="h-4 w-px bg-slate-200"></div>
        <div class="flex items-center gap-2">
          <span class="text-xs font-bold text-slate-800">DAST 扫描批次 #{{ id }}</span>
          <span
            v-if="detail"
            class="px-2 py-0.5 rounded-full text-xs font-medium inline-flex items-center gap-1.5"
            :class="statusBadgeStyle(detail.scan.status)"
          >
            <span class="w-1.5 h-1.5 rounded-full" :class="statusDotStyle(detail.scan.status)"></span>
            {{ statusText(detail.scan.status) }}
          </span>
        </div>
        <div v-if="detail" class="hidden md:flex items-center gap-2 text-xs text-slate-400 font-mono">
          <span>任务 {{ detail.scan.finished_tasks }}/{{ detail.scan.total_tasks }}</span>
          <span>失败 {{ detail.scan.failed_tasks }}</span>
        </div>
      </div>

      <div class="flex items-center gap-3">
        <span class="text-xs text-slate-500 font-medium">
          批次发现 <strong class="text-rose-600 font-bold">{{ findings.length }}</strong> 处漏洞
          <template v-if="selectedTask">
            （当前主机 <strong class="text-slate-800">{{ currentTaskFindingCount }}</strong> 处）
          </template>
        </span>
        <a-button size="small" :loading="loading" @click="refreshAll">
          <template #icon><RotateCw class="w-3 h-3 inline-block mr-1" /></template>
          刷新
        </a-button>
      </div>
    </div>

    <!-- 主体区域：左侧任务列表，右侧漏洞与任务详情 -->
    <div class="flex-1 min-h-0 flex gap-3 overflow-hidden">
      <!-- 任务列表 -->
      <div class="w-96 shrink-0 bg-white rounded-xl border border-slate-200/80 shadow-2xs overflow-hidden flex flex-col">
        <div class="px-4 py-2 border-b border-slate-100 text-xs font-bold text-slate-800 shrink-0 flex items-center gap-2">
          <Server class="w-3.5 h-3.5 text-blue-500" />
          资产任务
        </div>
        <div class="flex-1 overflow-y-auto">
          <a-spin :spinning="loading">
            <div
              v-for="task in detail?.tasks || []"
              :key="task.id"
              @click="selectTask(task)"
              class="px-4 py-2.5 border-b border-slate-100 cursor-pointer transition-colors"
              :class="String(selectedTaskId) === String(task.id) ? 'bg-blue-50/80 border-l-4 border-l-blue-600 shadow-2xs' : 'hover:bg-slate-50'"
            >
              <div class="flex items-center justify-between gap-2">
                <span class="font-mono text-xs font-semibold text-slate-700 truncate">
                  {{ task.plan.asset.host }}
                </span>
                <span
                  class="px-1.5 py-0.2 rounded text-[10px] font-medium"
                  :class="statusBadgeStyle(task.status)"
                >
                  {{ statusText(task.status) }}
                </span>
              </div>
              <div class="text-[10px] text-slate-400 font-mono mt-1 flex items-center justify-between">
                <span>#{{ task.id }} · {{ task.plan.asset.cluster_id }} / {{ task.plan.asset.network_zone }}</span>
                <span v-if="getTaskFindingCount(task) > 0" class="text-rose-600 font-bold">
                  {{ getTaskFindingCount(task) }} 处漏洞
                </span>
                <span v-else-if="task.status === 'success'" class="text-emerald-600 font-medium">
                  无风险
                </span>
              </div>
              <div v-if="task.error" class="text-[10px] text-rose-600 mt-0.5 truncate" :title="task.error">{{ task.error }}</div>
            </div>
            <div v-if="(detail?.tasks || []).length === 0" class="py-12 text-center text-xs text-slate-400">
              该批次还没有任务
            </div>
          </a-spin>
        </div>
      </div>

      <!-- 右侧：任务结果 + 漏洞列表 -->
      <div class="flex-1 min-w-0 flex flex-col gap-3 overflow-hidden">
        <!-- 任务结果卡片 -->
        <div class="bg-white rounded-xl border border-slate-200/80 shadow-2xs max-h-[50%] shrink-0 overflow-y-auto">
          <div class="px-4 py-2 border-b border-slate-100 flex items-center justify-between sticky top-0 z-10 bg-white">
            <div class="flex items-center gap-2">
              <Activity class="w-3.5 h-3.5 text-blue-500" />
              <span class="text-xs font-bold text-slate-800">
                任务结果
                <span v-if="selectedTask" class="text-slate-600 font-mono text-xs font-normal">
                  ({{ selectedTask.plan.asset.host }})
                </span>
              </span>
              <span v-if="taskDetail" class="font-mono text-[11px] text-blue-600 bg-blue-50 px-1.5 py-0.5 rounded border border-blue-200">
                #{{ taskDetail.task.id }}
              </span>
            </div>
            <span v-if="taskDetail" class="text-[11px] text-slate-400 font-mono">
              Worker: {{ taskDetail.task.worker_id || '等待调度' }}
            </span>
          </div>

          <!-- 执行失败/异常报告完整面板 -->
          <div v-if="taskDetail?.task?.error" class="m-3 p-3 rounded-lg bg-rose-50 border border-rose-200">
            <div class="flex items-center justify-between mb-2">
              <span class="text-xs font-semibold text-rose-800 flex items-center gap-1.5">
                <AlertCircle class="w-4 h-4 text-rose-600" />
                执行失败异常诊断报告
              </span>
              <a-button
                size="small"
                type="link"
                class="!p-0 !h-auto text-rose-600 hover:text-rose-700 text-xs font-medium"
                @click="copyError(taskDetail.task.error)"
              >
                复制完整错误
              </a-button>
            </div>
            <pre class="text-xs font-mono text-rose-950 bg-white/80 p-2.5 rounded border border-rose-100/80 whitespace-pre-wrap break-all select-text leading-relaxed">{{ taskDetail.task.error }}</pre>
          </div>
          <div class="p-3 grid grid-cols-2 xl:grid-cols-4 gap-3 text-xs">
            <div>
              <div class="text-slate-400 mb-1">解析地址</div>
              <div class="font-mono text-slate-700 break-all">
                {{ taskDetail?.result?.resolved_ips?.join(', ') || '—' }}
              </div>
            </div>
            <div>
              <div class="text-slate-400 mb-1">端口状态</div>
              <div class="font-mono text-slate-700">
                {{ taskDetail?.result?.ports?.length || 0 }} 个
              </div>
            </div>
            <div>
              <div class="text-slate-400 mb-1">未登记服务</div>
              <div class="font-mono" :class="(taskDetail?.unregistered?.length || 0) > 0 ? 'text-amber-600' : 'text-slate-700'">
                {{ taskDetail?.unregistered?.length || 0 }} 个
              </div>
            </div>
            <div>
              <div class="text-slate-400 mb-1">检查统计</div>
              <div class="font-mono text-slate-700">
                <template v-if="taskDetail?.result?.executed_checks != null">
                  执行 {{ taskDetail.result.executed_checks }} / 失败 {{ taskDetail.result.failed_checks ?? 0 }}
                </template>
                <template v-else>引擎未提供统计</template>
              </div>
            </div>
          </div>
          <div v-if="taskDetail?.unregistered?.length" class="px-3 pb-3">
            <div class="text-[11px] text-slate-400 mb-1">未登记端点</div>
            <a-space :size="4" wrap>
              <a-tag
                v-for="svc in taskDetail.unregistered"
                :key="`${svc.endpoint.host}:${svc.endpoint.port}/${svc.endpoint.transport}`"
                color="orange"
                class="!text-[10px] !font-mono !mr-0"
              >
                {{ svc.application_protocol || 'unknown' }}
                {{ svc.endpoint.host }}:{{ svc.endpoint.port }}/{{ svc.endpoint.transport }}
              </a-tag>
            </a-space>
          </div>
          <div v-if="groupedCoverage.length" class="px-3 pb-3">
            <div class="text-[11px] text-slate-400 mb-1">
              覆盖缺口（共 {{ groupedCoverage.length }} 项）
            </div>
            <a-space :size="4" wrap>
              <a-tooltip
                v-for="(item, idx) in groupedCoverage"
                :key="idx"
                :title="item.templates.length ? `涉及 ${item.count} 个规则模板: ${item.templates.slice(0, 5).join(', ')}${item.templates.length > 5 ? ' 等' : ''}` : undefined"
              >
                <a-tag color="default" class="!text-[10px] !font-mono !mr-0 cursor-default">
                  {{ item.endpoint }} · {{ coverageReasonText(item.reason) }}
                  <span v-if="item.count > 1" class="text-slate-400 font-sans ml-1">×{{ item.count }}</span>
                </a-tag>
              </a-tooltip>
            </a-space>
          </div>
        </div>

        <!-- 漏洞列表 -->
        <div class="flex-1 min-h-0 bg-white rounded-xl border border-slate-200/80 shadow-2xs overflow-hidden flex flex-col">
          <div class="px-4 py-2 border-b border-slate-100 flex items-center justify-between shrink-0">
            <div class="flex items-center gap-2">
              <ShieldAlert class="w-3.5 h-3.5 text-rose-500" />
              <span class="text-xs font-bold text-slate-800">漏洞列表</span>
              <span class="text-[11px] text-slate-400">共 {{ displayedFindings.length }} 条</span>
            </div>
            <a-radio-group v-model:value="findingScope" size="small">
              <a-radio-button value="task">
                当前主机 ({{ currentTaskFindingCount }})
              </a-radio-button>
              <a-radio-button value="all">
                全部批次 ({{ findings.length }})
              </a-radio-button>
            </a-radio-group>
          </div>
          <div class="flex-1 overflow-y-auto">
            <a-table
              :columns="findingColumns"
              :data-source="displayedFindings"
              :loading="taskDetailLoading || loading"
              row-key="key"
              size="small"
              :pagination="{ pageSize: 10, showSizeChanger: false }"
              :custom-row="customRow"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'severity'">
                  <span class="px-1.5 py-0.2 rounded text-[10px] font-bold uppercase" :class="severityStyle(record.severity)">
                    {{ severityText(record.severity) }}
                  </span>
                </template>
                <template v-else-if="column.key === 'title'">
                  <div class="text-xs font-medium text-slate-800">{{ record.title }}</div>
                  <div class="text-[10px] font-mono text-slate-400">{{ record.template_id }} · {{ record.matcher_name }}</div>
                </template>
                <template v-else-if="column.key === 'endpoint'">
                  <span class="text-[11px] font-mono text-slate-600">
                    {{ record.endpoint.host }}:{{ record.endpoint.port }}/{{ record.endpoint.transport }}
                  </span>
                </template>
                <template v-else-if="column.key === 'cves'">
                  <a-space :size="4" wrap>
                    <a-tag v-for="cve in record.cves" :key="cve" color="red" class="!text-[10px] !mr-0">{{ cve }}</a-tag>
                    <a-tag v-for="cwe in record.cwes" :key="cwe" color="orange" class="!text-[10px] !mr-0">{{ cwe }}</a-tag>
                  </a-space>
                </template>
                <template v-else-if="column.key === 'matched_at'">
                  <span class="text-[11px] font-mono text-slate-500">{{ record.matched_at }}</span>
                </template>
                <template v-else-if="column.key === 'action'">
                  <a-button type="link" size="small" class="!p-0 text-blue-600 font-medium text-xs" @click.stop="viewFinding(record)">
                    查看详情
                  </a-button>
                </template>
              </template>
            </a-table>
          </div>
        </div>
      </div>
    </div>

    <!-- 漏洞验证详情抽屉 -->
    <a-drawer
      v-model:open="showFindingDrawer"
      title="漏洞详情与验证证据"
      width="720px"
      placement="right"
    >
      <div v-if="activeFinding" class="space-y-4 text-xs">
        <!-- 基础标题卡片 -->
        <div class="bg-slate-50 p-3.5 rounded-xl border border-slate-200/80">
          <div class="flex items-center gap-2 mb-2">
            <span class="px-2 py-0.5 rounded text-[11px] font-bold uppercase" :class="severityStyle(activeFinding.severity)">
              {{ severityText(activeFinding.severity) }}
            </span>
            <span class="text-sm font-bold text-slate-800">{{ activeFinding.title }}</span>
          </div>
          <div class="grid grid-cols-2 gap-2 text-slate-600 font-mono text-[11px] mt-2 pt-2 border-t border-slate-200/60">
            <div><span class="text-slate-400">规则模板:</span> {{ activeFinding.template_id }}</div>
            <div><span class="text-slate-400">匹配器:</span> {{ activeFinding.matcher_name || '默认匹配' }}</div>
            <div><span class="text-slate-400">端点地址:</span> {{ activeFinding.endpoint.host }}:{{ activeFinding.endpoint.port }}/{{ activeFinding.endpoint.transport }}</div>
            <div><span class="text-slate-400">命中时间:</span> {{ activeFinding.matched_at }}</div>
          </div>
          <div v-if="activeFinding.target_url" class="mt-1 text-[11px] font-mono break-all text-blue-700">
            <span class="text-slate-400">目标 URL:</span> {{ activeFinding.target_url }}
          </div>
          <div v-if="activeFinding.cves?.length || activeFinding.cwes?.length" class="mt-2.5 flex items-center gap-1.5 flex-wrap">
            <span class="text-slate-400 text-[11px]">关联编号:</span>
            <a-tag v-for="cve in activeFinding.cves" :key="cve" color="red" class="!text-[10px]">{{ cve }}</a-tag>
            <a-tag v-for="cwe in activeFinding.cwes" :key="cwe" color="orange" class="!text-[10px]">{{ cwe }}</a-tag>
          </div>
        </div>

        <!-- 漏洞描述 -->
        <div v-if="activeFinding.description" class="bg-white p-3.5 rounded-xl border border-slate-200/80">
          <div class="font-bold text-slate-700 mb-1.5 flex items-center gap-1.5">
            <FileText class="w-3.5 h-3.5 text-blue-500" />
            漏洞描述与说明
          </div>
          <p class="text-slate-600 leading-relaxed whitespace-pre-wrap">{{ activeFinding.description }}</p>
        </div>

        <!-- 动态提取特征值 -->
        <div v-if="activeFinding.evidence?.extracted_values?.length" class="bg-white p-3.5 rounded-xl border border-slate-200/80">
          <div class="font-bold text-slate-700 mb-1.5 flex items-center gap-1.5">
            <CheckCircle2 class="w-3.5 h-3.5 text-emerald-500" />
            命中提取特征值 (Extracted Results)
          </div>
          <div class="flex flex-wrap gap-1.5">
            <span
              v-for="(val, idx) in activeFinding.evidence.extracted_values"
              :key="idx"
              class="px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono text-[11px]"
            >
              {{ val }}
            </span>
          </div>
        </div>

        <!-- HTTP 请求报文 -->
        <div class="bg-white p-3.5 rounded-xl border border-slate-200/80">
          <div class="flex items-center justify-between mb-2">
            <div class="font-bold text-slate-700 flex items-center gap-1.5">
              <Send class="w-3.5 h-3.5 text-blue-500" />
              HTTP 验证请求报文 (Request)
            </div>
            <a-button
              v-if="activeFinding.evidence?.request"
              size="small"
              type="link"
              class="!p-0 !h-auto text-blue-600 font-medium"
              @click="copyText(activeFinding.evidence.request, '请求报文已复制')"
            >
              复制请求
            </a-button>
          </div>
          <pre
            v-if="activeFinding.evidence?.request"
            class="bg-slate-900 text-slate-100 p-3 rounded-lg font-mono text-[11px] overflow-x-auto whitespace-pre-wrap break-all select-text leading-relaxed max-h-64"
          >{{ activeFinding.evidence.request }}</pre>
          <div v-else class="text-slate-400 py-3 text-center bg-slate-50 rounded-lg">
            引擎未记录 HTTP 请求报文（TCP/SSL 原生探测或无独立回放包）
          </div>
        </div>

        <!-- HTTP 响应报文 -->
        <div class="bg-white p-3.5 rounded-xl border border-slate-200/80">
          <div class="flex items-center justify-between mb-2">
            <div class="font-bold text-slate-700 flex items-center gap-1.5">
              <Inbox class="w-3.5 h-3.5 text-emerald-500" />
              HTTP 验证响应报文 (Response)
            </div>
            <a-button
              v-if="activeFinding.evidence?.response"
              size="small"
              type="link"
              class="!p-0 !h-auto text-emerald-600 font-medium"
              @click="copyText(activeFinding.evidence.response, '响应报文已复制')"
            >
              复制响应
            </a-button>
          </div>
          <pre
            v-if="activeFinding.evidence?.response"
            class="bg-slate-900 text-slate-100 p-3 rounded-lg font-mono text-[11px] overflow-x-auto whitespace-pre-wrap break-all select-text leading-relaxed max-h-96"
          >{{ activeFinding.evidence.response }}</pre>
          <div v-else class="text-slate-400 py-3 text-center bg-slate-50 rounded-lg">
            引擎未记录 HTTP 响应报文
          </div>
        </div>

        <!-- 参考链接 -->
        <div v-if="activeFinding.references?.length" class="bg-white p-3.5 rounded-xl border border-slate-200/80">
          <div class="font-bold text-slate-700 mb-1.5 flex items-center gap-1.5">
            <ExternalLink class="w-3.5 h-3.5 text-slate-400" />
            官方参考公告与链接
          </div>
          <ul class="list-disc list-inside space-y-1 text-slate-500 text-[11px]">
            <li v-for="ref in activeFinding.references" :key="ref" class="truncate">
              <a :href="ref" target="_blank" rel="noopener noreferrer" class="text-blue-600 hover:underline">
                {{ ref }}
              </a>
            </li>
          </ul>
        </div>
      </div>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { ArrowLeft, RotateCw, Server, Activity, ShieldAlert, AlertCircle, FileText, Send, Inbox, ExternalLink, CheckCircle2 } from 'lucide-vue-next'
import { api } from '@/api'
import type { DastFinding, DastScanDetail, DastTask, DastTaskDetail } from '@/types'

const route = useRoute()
const router = useRouter()
const id = computed(() => String(route.params.id ?? ''))

const detail = ref<DastScanDetail | null>(null)
const taskDetail = ref<DastTaskDetail | null>(null)
const findings = ref<(DastFinding & { key: string })[]>([])
const selectedTaskId = ref('')
const loading = ref(false)
const taskDetailLoading = ref(false)
const findingScope = ref<'task' | 'all'>('task')

const selectedTask = computed<DastTask | null>(() => {
  return (detail.value?.tasks || []).find((t) => String(t.id) === String(selectedTaskId.value)) || null
})

const displayedFindings = computed(() => {
  if (findingScope.value === 'all') {
    return findings.value
  }
  if (!selectedTaskId.value) {
    return findings.value
  }
  const curTaskId = String(selectedTaskId.value)
  const curHost = selectedTask.value?.plan?.asset?.host
  return findings.value.filter((f) => {
    if (f.task_id && String(f.task_id) === curTaskId) {
      return true
    }
    if (curHost && f.endpoint?.host === curHost) {
      return true
    }
    return false
  })
})

const currentTaskFindingCount = computed(() => {
  if (!selectedTaskId.value) return 0
  const curTaskId = String(selectedTaskId.value)
  const curHost = selectedTask.value?.plan?.asset?.host
  return findings.value.filter((f) => {
    if (f.task_id && String(f.task_id) === curTaskId) return true
    if (curHost && f.endpoint?.host === curHost) return true
    return false
  }).length
})

function getTaskFindingCount(task: DastTask) {
  const tId = String(task.id)
  const host = task.plan?.asset?.host
  return findings.value.filter(
    (f) => (f.task_id && String(f.task_id) === tId) || (host && f.endpoint?.host === host)
  ).length
}

const showFindingDrawer = ref(false)
const activeFinding = ref<DastFinding | null>(null)

function viewFinding(finding: any) {
  activeFinding.value = finding as DastFinding
  showFindingDrawer.value = true
}

const customRow = (record: any) => ({
  onClick: () => viewFinding(record),
  class: 'cursor-pointer hover:bg-blue-50/50 transition-colors',
})

function copyText(text: string, msg: string = '已复制') {
  if (navigator?.clipboard) {
    navigator.clipboard.writeText(text).then(() => {
      message.success(msg)
    })
  } else {
    message.info('当前环境不支持直接复制')
  }
}

const findingColumns = [
  { title: '严重度', dataIndex: 'severity', key: 'severity', width: 90 },
  { title: '漏洞', key: 'title' },
  { title: '端点', key: 'endpoint', width: 220 },
  { title: 'CVE / CWE', key: 'cves', width: 180 },
  { title: '命中时间', dataIndex: 'matched_at', key: 'matched_at', width: 160 },
  { title: '操作', key: 'action', width: 90, align: 'center' as const },
]

function dedupFindings(raw: DastFinding[]): (DastFinding & { key: string })[] {
  const map = new Map<string, DastFinding & { key: string }>()
  for (let i = 0; i < raw.length; i++) {
    const item = raw[i]
    const host = item.endpoint?.host || ''
    const port = item.endpoint?.port != null ? item.endpoint.port : ''
    const transport = item.endpoint?.transport || ''
    const ruleKey = item.template_id || item.title || ''
    const key = `${host}:${port}/${transport}|${ruleKey}`
    const existing = map.get(key)
    if (!existing) {
      map.set(key, { ...item, key: `${ruleKey || 'f'}-${i}` })
    } else {
      if (!existing.evidence && item.evidence) {
        existing.evidence = item.evidence
      }
      if (item.matcher_name && !existing.matcher_name?.includes(item.matcher_name)) {
        existing.matcher_name = existing.matcher_name ? `${existing.matcher_name}, ${item.matcher_name}` : item.matcher_name
      }
      if (item.cves && item.cves.length > 0) {
        existing.cves = Array.from(new Set([...(existing.cves || []), ...item.cves]))
      }
      if (item.cwes && item.cwes.length > 0) {
        existing.cwes = Array.from(new Set([...(existing.cwes || []), ...item.cwes]))
      }
      if (item.references && item.references.length > 0) {
        existing.references = Array.from(new Set([...(existing.references || []), ...item.references]))
      }
    }
  }
  return Array.from(map.values())
}

let pollTimer: ReturnType<typeof setInterval> | null = null
let lastFinishedTasks = -1

async function load(silent = false) {
  if (!silent) loading.value = true
  try {
    let scanId = id.value
    let targetTaskId = (route.query.task_id as string) || selectedTaskId.value

    // 并发拉取批次概览与漏洞列表，消除串行瀑布请求
    const scanPromise = api.getDastScan(scanId).catch(async (e: any) => {
      try {
        const tDetail = await api.getDastTask(scanId)
        if (tDetail?.task?.scan_id) {
          scanId = String(tDetail.task.scan_id)
          targetTaskId = String(tDetail.task.id)
          return await api.getDastScan(scanId)
        }
      } catch {
        throw e
      }
      throw e
    })

    const isFirstLoad = !detail.value
    // 首次加载或已完成任务数有变化时才拉取漏洞列表，避免轮询重复全量拉取
    const shouldFetchFindings =
      isFirstLoad || (detail.value != null && detail.value.scan.finished_tasks !== lastFinishedTasks)
    const findingsPromise = shouldFetchFindings
      ? api.getDastScanFindings(scanId).catch(() => [] as DastFinding[])
      : Promise.resolve(null)

    // 优先获得批次详情
    const sDetail = await scanPromise
    detail.value = sDetail

    // 首屏主体骨架数据就绪后立即释放骨架屏，让用户快速看到主机列表与批次概览
    if (!silent) loading.value = false

    const tasks = sDetail?.tasks || []
    let selectPromise: Promise<void> | null = null
    if (tasks.length > 0) {
      const target = tasks.find((t) => String(t.id) === String(targetTaskId)) ?? tasks[0]
      const isCurTaskRunning =
        !taskDetail.value ||
        taskDetail.value.task.status === 'running' ||
        taskDetail.value.task.status === 'pending'
      if (isFirstLoad || isCurTaskRunning || selectedTaskId.value !== String(target.id)) {
        selectPromise = selectTask(target, true)
      }
    }

    // 并行等待漏洞数据与任务详情
    const [rawFindings] = await Promise.all([findingsPromise, selectPromise])
    if (rawFindings !== null) {
      findings.value = dedupFindings(rawFindings)
      lastFinishedTasks = sDetail?.scan?.finished_tasks ?? -1
    }

    const isOngoing = detail.value?.scan?.status === 'pending' || detail.value?.scan?.status === 'running'
    if (isOngoing && !pollTimer) {
      pollTimer = setInterval(() => {
        load(true)
      }, 3000)
    } else if (!isOngoing && pollTimer) {
      clearInterval(pollTimer)
      pollTimer = null
    }
  } catch (e: any) {
    if (!silent) message.error(e.message)
  } finally {
    if (!silent) loading.value = false
  }
}

async function selectTask(task: DastTask, silent = false) {
  selectedTaskId.value = String(task.id)
  if (route.query.task_id !== String(task.id)) {
    router.replace({ query: { ...route.query, task_id: String(task.id) } })
  }
  if (!silent) taskDetailLoading.value = true
  try {
    taskDetail.value = await api.getDastTask(task.id)
  } catch (e: any) {
    if (!silent) message.error(e.message)
  } finally {
    if (!silent) taskDetailLoading.value = false
  }
}

function refreshAll() {
  lastFinishedTasks = -1
  load()
}

onUnmounted(() => {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
})

function statusBadgeStyle(status: string) {
  return (
    {
      pending: 'bg-slate-100 text-slate-600 border border-slate-200',
      running: 'bg-blue-50 text-blue-600 border border-blue-200',
      success: 'bg-emerald-50 text-emerald-600 border border-emerald-200',
      failed: 'bg-rose-50 text-rose-600 border border-rose-200',
    }[status] ?? 'bg-slate-100 text-slate-600'
  )
}

function statusDotStyle(status: string) {
  return (
    {
      pending: 'bg-slate-400',
      running: 'bg-blue-500 animate-pulse',
      success: 'bg-emerald-500',
      failed: 'bg-rose-500',
    }[status] ?? 'bg-slate-400'
  )
}

function statusText(status: string) {
  return (
    {
      cancelled: '已取消',
      pending: '排队中',
      running: '执行中',
      success: '成功',
      failed: '失败',
    }[status] ?? status
  )
}

function severityStyle(severity: string) {
  return (
    {
      critical: 'bg-rose-600 text-white',
      high: 'bg-orange-500 text-white',
      medium: 'bg-amber-400 text-white',
      low: 'bg-blue-100 text-blue-700',
      info: 'bg-slate-100 text-slate-600',
      unknown: 'bg-slate-100 text-slate-500',
    }[severity] ?? 'bg-slate-100 text-slate-600'
  )
}

function severityText(severity: string) {
  return (
    {
      critical: '严重',
      high: '高危',
      medium: '中危',
      low: '低危',
      info: '信息',
      unknown: '未知',
    }[severity] ?? severity
  )
}

interface GroupedCoverage {
  endpoint: string
  reason: string
  count: number
  templates: string[]
}

const coverageReasonLabels: Record<string, string> = {
  protocol_mismatch: '协议不匹配',
  product_mismatch: '组件/产品不匹配',
  version_mismatch: '版本不匹配',
  insufficient_fingerprint: '服务指纹不足',
  unsupported_transport: '非支持传输协议',
  registered_service_not_confirmed_open: '登记端口未确认开放',
  registered_protocol_mismatch: '登记协议不一致',
  engine_execution_unconfirmed: '未命中 PoC 验证特征',
  engine_execution_statistics_unavailable: '统计数据不可用',
}

function coverageReasonText(reason: string) {
  return coverageReasonLabels[reason] || reason
}

const groupedCoverage = computed<GroupedCoverage[]>(() => {
  const issues = taskDetail.value?.result?.coverage || []
  const map = new Map<string, GroupedCoverage>()
  for (const issue of issues) {
    const host = issue.endpoint?.host || 'unknown'
    const port = issue.endpoint?.port != null ? issue.endpoint.port : ''
    const transport = issue.endpoint?.transport ? `/${issue.endpoint.transport}` : ''
    const ep = port ? `${host}:${port}${transport}` : host
    const reason = issue.reason || 'unknown'
    const key = `${ep}|${reason}`
    const existing = map.get(key)
    if (existing) {
      existing.count++
      if (issue.template_id && !existing.templates.includes(issue.template_id)) {
        existing.templates.push(issue.template_id)
      }
    } else {
      map.set(key, {
        endpoint: ep,
        reason,
        count: 1,
        templates: issue.template_id ? [issue.template_id] : [],
      })
    }
  }
  return Array.from(map.values())
})

function copyError(text: string) {
  if (navigator?.clipboard) {
    navigator.clipboard.writeText(text).then(() => {
      message.success('错误日志已复制到剪切板')
    })
  } else {
    message.info('当前浏览器环境不支持直接复制')
  }
}

onMounted(load)
</script>
