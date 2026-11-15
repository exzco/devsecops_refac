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
          发现 <strong class="text-rose-600 font-bold">{{ findings.length }}</strong> 处漏洞
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
              :class="selectedTaskId === task.id ? 'bg-blue-50/70' : 'hover:bg-slate-50'"
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
              <div class="text-[10px] text-slate-400 font-mono mt-1 truncate">
                #{{ task.id }} · {{ task.plan.asset.cluster_id }} / {{ task.plan.asset.network_zone }}
              </div>
              <div v-if="task.error" class="text-[10px] text-rose-600 mt-0.5 truncate">{{ task.error }}</div>
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
        <div class="bg-white rounded-xl border border-slate-200/80 shadow-2xs flex flex-col overflow-hidden shrink-0">
          <div class="px-4 py-2 border-b border-slate-100 flex items-center justify-between shrink-0">
            <div class="flex items-center gap-2">
              <Activity class="w-3.5 h-3.5 text-blue-500" />
              <span class="text-xs font-bold text-slate-800">任务结果</span>
              <span v-if="taskDetail" class="font-mono text-xs text-slate-500">#{{ taskDetail.task.id }}</span>
            </div>
            <span v-if="taskDetail" class="text-[11px] text-slate-400 font-mono">
              Worker: {{ taskDetail.task.worker_id || '等待调度' }}
            </span>
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
          <div v-if="taskDetail?.result?.coverage?.length" class="px-3 pb-3">
            <div class="text-[11px] text-slate-400 mb-1">覆盖缺口</div>
            <a-space :size="4" wrap>
              <a-tag
                v-for="(issue, idx) in taskDetail.result.coverage"
                :key="idx"
                class="!text-[10px] !font-mono !mr-0"
              >
                {{ issue.endpoint.host }}:{{ issue.endpoint.port }} · {{ issue.reason }}
              </a-tag>
            </a-space>
          </div>
        </div>

        <!-- 漏洞列表 -->
        <div class="flex-1 min-h-0 bg-white rounded-xl border border-slate-200/80 shadow-2xs overflow-hidden flex flex-col">
          <div class="px-4 py-2 border-b border-slate-100 flex items-center gap-2 shrink-0">
            <ShieldAlert class="w-3.5 h-3.5 text-rose-500" />
            <span class="text-xs font-bold text-slate-800">漏洞</span>
            <span class="text-[11px] text-slate-400">共 {{ findings.length }} 条</span>
          </div>
          <div class="flex-1 overflow-y-auto">
            <a-table
              :columns="findingColumns"
              :data-source="findings"
              :loading="loading"
              row-key="key"
              size="small"
              :pagination="{ pageSize: 10, showSizeChanger: false }"
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
              </template>
            </a-table>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { ArrowLeft, RotateCw, Server, Activity, ShieldAlert } from 'lucide-vue-next'
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

const findingColumns = [
  { title: '严重度', dataIndex: 'severity', key: 'severity', width: 90 },
  { title: '漏洞', key: 'title' },
  { title: '端点', key: 'endpoint', width: 220 },
  { title: 'CVE / CWE', key: 'cves', width: 180 },
  { title: '命中时间', dataIndex: 'matched_at', key: 'matched_at', width: 180 },
]

async function load() {
  loading.value = true
  try {
    detail.value = await api.getDastScan(id.value)
    findings.value = (await api.getDastScanFindings(id.value)).map((f, idx) => ({ ...f, key: `${f.template_id}-${idx}` }))
    const tasks = detail.value.tasks
    if (tasks.length > 0) {
      const target = tasks.find((t) => t.id === selectedTaskId.value) ?? tasks[0]
      await selectTask(target)
    }
  } catch (e: any) {
    message.error(e.message)
  } finally {
    loading.value = false
  }
}

async function selectTask(task: DastTask) {
  selectedTaskId.value = task.id
  try {
    taskDetail.value = await api.getDastTask(task.id)
  } catch (e: any) {
    message.error(e.message)
  }
}

function refreshAll() {
  load()
}

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

onMounted(load)
</script>
