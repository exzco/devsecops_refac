<template>
  <div class="h-full flex flex-col overflow-hidden gap-4">
    <!-- 顶部 4 块指标统计卡片（固定高度） -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 shrink-0">
      <!-- 1. 已接入源码工程 -->
      <div class="bg-white rounded-xl border border-slate-200/80 p-5 shadow-2xs flex flex-col justify-between">
        <div class="flex items-start justify-between">
          <div>
            <div class="text-xs text-slate-400 font-medium">已接入源码工程</div>
            <div class="text-2xl font-bold text-slate-800 mt-2">{{ stats?.repos ?? '—' }}</div>
          </div>
          <div class="w-10 h-10 rounded-lg border border-slate-200/70 flex items-center justify-center text-slate-500 bg-slate-50/60">
            <FileArchive class="w-5 h-5 text-amber-500" />
          </div>
        </div>
        <div class="text-xs text-slate-400 mt-4">接收 Go, Java, TS, Python 源码压缩包</div>
      </div>

      <!-- 2. SAST 静态扫描任务 -->
      <div class="bg-white rounded-xl border border-slate-200/80 p-5 shadow-2xs flex flex-col justify-between">
        <div class="flex items-start justify-between">
          <div>
            <div class="text-xs text-slate-400 font-medium">SAST 静态扫描任务</div>
            <div class="text-2xl font-bold text-slate-800 mt-2">{{ stats?.scans ?? '—' }}</div>
          </div>
          <div class="w-10 h-10 rounded-lg border border-slate-200/70 flex items-center justify-center text-slate-500 bg-slate-50/60">
            <Code2 class="w-5 h-5 text-slate-600" />
          </div>
        </div>
        <div class="text-xs text-slate-400 mt-4">{{ stats?.findings ?? '—' }} 处静态代码隐患点</div>
      </div>

      <!-- 3. DAST 动态扫描任务 -->
      <div class="bg-white rounded-xl border border-slate-200/80 p-5 shadow-2xs flex flex-col justify-between">
        <div class="flex items-start justify-between">
          <div>
            <div class="text-xs text-slate-400 font-medium">DAST 动态扫描任务</div>
            <div class="text-2xl font-bold text-slate-800 mt-2">{{ stats?.batches ?? '—' }}</div>
          </div>
          <div class="w-10 h-10 rounded-lg border border-slate-200/70 flex items-center justify-center text-slate-500 bg-slate-50/60">
            <Crosshair class="w-5 h-5 text-slate-600" />
          </div>
        </div>
        <div class="text-xs text-slate-400 mt-4">历史发现 {{ stats?.ports ?? '—' }} 个开放端口（{{ stats?.vulnerabilities ?? '—' }} 条漏洞记录）</div>
      </div>

      <!-- 4. Worker 节点 -->
      <div class="bg-white rounded-xl border border-slate-200/80 p-5 shadow-2xs flex flex-col justify-between">
        <div class="flex items-start justify-between">
          <div>
            <div class="text-xs text-slate-400 font-medium">Worker 节点</div>
            <div class="text-2xl font-bold text-slate-800 mt-2">
              <span>{{ onlineWorkers }}</span>
              <span class="text-sm font-normal text-slate-400 ml-1">/ {{ totalWorkers }} 在线</span>
            </div>
          </div>
          <div
            class="w-10 h-10 rounded-lg border flex items-center justify-center"
            :class="onlineWorkers > 0 ? 'border-emerald-200 text-emerald-500 bg-emerald-50/40' : 'border-slate-200 text-slate-400 bg-slate-50'"
          >
            <Server class="w-5 h-5" />
          </div>
        </div>
        <div v-if="onlineWorkers > 0" class="text-xs text-emerald-600 mt-4 flex items-center gap-1 font-medium">
          <CheckCircle2 class="w-3.5 h-3.5" /> 在线节点 (SAST: {{ onlineSastWorkers }} | DAST: {{ onlineDastWorkers }})
        </div>
        <div v-else class="text-xs text-amber-600 mt-4 flex items-center gap-1 font-medium">
          <AlertCircle class="w-3.5 h-3.5" /> 暂无在线 Worker (SAST: 0 | DAST: 0)
        </div>
      </div>
    </div>

    <!-- 主体区域：Worker 节点列表卡片（卡片内独立滚动） -->
    <div class="bg-white rounded-xl border border-slate-200/80 p-5 shadow-2xs flex-1 min-h-0 flex flex-col overflow-hidden">
      <!-- 列表标题与操作（固定） -->
      <div class="flex items-center justify-between pb-4 border-b border-slate-100 shrink-0 flex-wrap gap-3">
        <div class="flex items-center gap-3">
          <div class="w-7 h-7 rounded-md bg-slate-900 text-white flex items-center justify-center text-xs shadow-xs">
            <Settings class="w-3.5 h-3.5" />
          </div>
          <span class="font-bold text-slate-800 text-sm">worker 节点列表</span>
          <span
            v-if="onlineWorkers > 0"
            class="px-2.5 py-0.5 rounded-full text-xs font-medium text-emerald-600 bg-emerald-50 border border-emerald-200 flex items-center gap-1.5"
          >
            <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
            环境正常
          </span>
          <span
            v-else
            class="px-2.5 py-0.5 rounded-full text-xs font-medium text-amber-600 bg-amber-50 border border-amber-200 flex items-center gap-1.5"
          >
            <span class="w-1.5 h-1.5 rounded-full bg-amber-500"></span>
            暂无节点在线
          </span>
        </div>

        <div class="flex items-center gap-2.5">
          <a-button size="small" :loading="loading" @click="fetchData">
            <template #icon><RotateCw class="w-3 h-3 inline-block mr-1" /></template>
            刷新状态
          </a-button>

          <!-- 刷新状态右侧：在线与掉线筛选功能 -->
          <div class="inline-flex p-0.5 rounded-lg bg-slate-100 border border-slate-200/80 text-xs">
            <button
              @click="workerFilter = 'all'"
              class="px-2.5 py-1 rounded-md transition-all cursor-pointer font-medium"
              :class="workerFilter === 'all' ? 'bg-white text-slate-900 shadow-2xs font-semibold' : 'text-slate-500 hover:text-slate-800'"
            >
              全部 ({{ workers.length }})
            </button>
            <button
              @click="workerFilter = 'online'"
              class="px-2.5 py-1 rounded-md transition-all cursor-pointer font-medium flex items-center gap-1.5"
              :class="workerFilter === 'online' ? 'bg-white text-emerald-700 shadow-2xs font-semibold' : 'text-slate-500 hover:text-emerald-700'"
            >
              <span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
              <span>在线 ({{ onlineWorkers }})</span>
            </button>
            <button
              @click="workerFilter = 'offline'"
              class="px-2.5 py-1 rounded-md transition-all cursor-pointer font-medium flex items-center gap-1.5"
              :class="workerFilter === 'offline' ? 'bg-white text-rose-700 shadow-2xs font-semibold' : 'text-slate-500 hover:text-rose-700'"
            >
              <span class="w-1.5 h-1.5 rounded-full bg-slate-400"></span>
              <span>掉线 ({{ offlineWorkers }})</span>
            </button>
          </div>
        </div>
      </div>

      <!-- Worker 节点卡片列表（独立滚动） -->
      <div class="mt-4 space-y-4 flex-1 overflow-y-auto pr-1">
        <!-- 真实 Worker 节点 -->
        <div
          v-for="w in filteredWorkers"
          :key="`${w.kind}:${w.kind === 'SAST' ? w.status.worker_id : w.status.instance_id}`"
          class="border border-slate-200/90 rounded-xl p-5 bg-white shadow-2xs transition-all hover:border-slate-300"
        >
          <!-- 节点元信息头条 -->
          <div class="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-100">
            <div class="flex items-center flex-wrap gap-2.5">
              <span class="px-2.5 py-0.5 rounded text-xs font-semibold bg-indigo-50 text-indigo-600 tracking-wider">
                {{ w.kind }} WORKER
              </span>
              <span class="font-bold text-slate-800 text-sm font-mono">{{ w.kind === 'SAST' ? w.status.worker_id : w.status.instance_id }}</span>
              <span
                class="px-2 py-0.5 rounded-full text-xs font-medium flex items-center gap-1"
                :class="w.status.online ? 'bg-emerald-50 text-emerald-600 border border-emerald-200' : 'bg-slate-100 text-slate-500'"
              >
                <span class="w-1.5 h-1.5 rounded-full" :class="w.status.online ? 'bg-emerald-500' : 'bg-slate-400'"></span>
                {{ w.status.online ? '在线' : '掉线' }}
              </span>
              <span
                v-if="w.status.online"
                class="px-2 py-0.5 rounded text-xs border border-teal-200 text-teal-600 bg-teal-50/40 font-medium"
              >
                ✓ 环境就绪
              </span>
              <span
                v-else
                class="px-2 py-0.5 rounded text-xs border border-rose-200 text-rose-600 bg-rose-50/40 font-medium"
              >
                ! 心跳中断
              </span>
            </div>
            <div class="text-xs text-slate-500 font-mono flex items-center gap-3 flex-wrap">
              <span>最后心跳: {{ formatLastSeen(w.status.last_seen_at) }}</span>
            </div>
          </div>

          <!-- 依赖与外部工具核验内容 -->
          <div v-if="w.kind === 'SAST'" class="pt-3">
            <div class="flex items-center justify-between text-xs text-slate-500 font-medium mb-3">
              <span>依赖与网络核验</span>
              <span v-if="w.status.work_root" class="font-mono text-slate-400 text-[11px]">工作区: {{ w.status.work_root }}</span>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
              <!-- 项 1: CodeQL 分析引擎 -->
              <div class="border border-slate-200/70 rounded-lg p-3 bg-slate-50/50">
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-1.5 text-xs font-semibold text-slate-800">
                    <CheckCircle2 v-if="w.status.codeql_ok" class="w-3.5 h-3.5 text-teal-500" />
                    <AlertCircle v-else class="w-3.5 h-3.5 text-rose-500" />
                    <span>CodeQL 分析引擎</span>
                  </div>
                  <span class="text-[10px] text-slate-400 bg-slate-200/60 px-1.5 py-0.5 rounded">强依赖</span>
                </div>
                <div class="text-[11px] text-slate-500 mt-1.5 font-mono truncate" :title="w.status.codeql_path">
                  {{ w.status.codeql_path }} ({{ w.status.codeql_ok ? '已就绪' : '未检测到' }})
                </div>
              </div>

              <!-- 项 2: 规则套件索引 -->
              <div class="border border-slate-200/70 rounded-lg p-3 bg-slate-50/50">
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-1.5 text-xs font-semibold text-slate-800">
                    <CheckCircle2 class="w-3.5 h-3.5 text-teal-500" />
                    <span>SAST 查询套件</span>
                  </div>
                  <span class="text-[10px] text-slate-400 bg-slate-200/60 px-1.5 py-0.5 rounded">强依赖</span>
                </div>
                <div class="text-[11px] text-slate-500 mt-1.5 font-mono truncate">
                  <router-link to="/sast/config" class="text-blue-600">查看当前生效套件</router-link>
                </div>
              </div>

              <!-- 项 3: 队列连通性 -->
              <div class="border border-slate-200/70 rounded-lg p-3 bg-slate-50/50">
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-1.5 text-xs font-semibold text-slate-800">
                    <CheckCircle2 class="w-3.5 h-3.5 text-teal-500" />
                    <span>基础网络与 Redis 连通性</span>
                  </div>
                  <span class="text-[10px] text-emerald-600 bg-emerald-50 px-1.5 py-0.5 rounded font-medium">正常</span>
                </div>
                <div class="text-[11px] text-slate-500 mt-1.5 font-mono truncate">
                  队列: sast:scan:queue (心跳 10s 正常)
                </div>
              </div>
            </div>
          </div>
          <div v-else class="pt-3 grid grid-cols-1 md:grid-cols-3 gap-3">
            <div class="border border-slate-200/70 rounded-lg p-3 bg-slate-50/50">
              <div class="text-xs font-semibold text-slate-800">集群</div>
              <div class="text-[11px] text-slate-500 mt-1.5 font-mono">{{ w.status.cluster_id }}</div>
            </div>
            <div class="border border-slate-200/70 rounded-lg p-3 bg-slate-50/50">
              <div class="text-xs font-semibold text-slate-800">网络区域</div>
              <div class="text-[11px] text-slate-500 mt-1.5 font-mono">{{ w.status.network_zone }}</div>
            </div>
            <div class="border border-slate-200/70 rounded-lg p-3 bg-slate-50/50">
              <div class="text-xs font-semibold text-slate-800">模板版本</div>
              <div class="text-[11px] text-slate-500 mt-1.5 font-mono">{{ w.status.template_version }}</div>
            </div>
          </div>
        </div>

        <!-- 节点列表为空提示 -->
        <div
          v-if="!loading && filteredWorkers.length === 0"
          class="text-center py-12 border border-dashed border-slate-200 rounded-xl bg-slate-50/30"
        >
          <Server class="w-8 h-8 text-slate-300 mx-auto mb-2" />
          <div class="text-slate-500 text-sm font-medium">
            {{ workers.length === 0 ? '暂无注册的 Worker 节点' : '没有符合当前筛选状态的 Worker 节点' }}
          </div>
          <div class="text-xs text-slate-400 mt-1">
            {{ workers.length === 0 ? '请启动 SAST 或 DAST Worker' : '可尝试切换上方“全部 / 在线 / 掉线”筛选器' }}
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import 'dayjs/locale/zh-cn'
import {
  FileArchive,
  Code2,
  Crosshair,
  Server,
  CheckCircle2,
  AlertCircle,
  Settings,
  RotateCw,
} from 'lucide-vue-next'
import { api } from '@/api'
import type { WorkerStatus, DastWorkerStatus } from '@/types'

dayjs.extend(relativeTime)
dayjs.locale('zh-cn')

const loading = ref(false)
const stats = ref<Awaited<ReturnType<typeof api.dashboard>>>()
type DashboardWorker =
  | { kind: 'SAST'; status: WorkerStatus }
  | { kind: 'DAST'; status: DastWorkerStatus }

const workers = ref<DashboardWorker[]>([])
const workerFilter = ref<'all' | 'online' | 'offline'>('all')

const filteredWorkers = computed(() => {
  if (workerFilter.value === 'online') {
    return workers.value.filter((w) => w.status.online)
  }
  if (workerFilter.value === 'offline') {
    return workers.value.filter((w) => !w.status.online)
  }
  return workers.value
})

const totalWorkers = computed(() => {
  return workers.value.length
})

const onlineWorkers = computed(() => {
  return workers.value.filter((w) => w.status.online).length
})

const onlineSastWorkers = computed(() => workers.value.filter((w) => w.kind === 'SAST' && w.status.online).length)
const onlineDastWorkers = computed(() => workers.value.filter((w) => w.kind === 'DAST' && w.status.online).length)

const offlineWorkers = computed(() => {
  return workers.value.filter((w) => !w.status.online).length
})

function formatLastSeen(timeStr: string | null) {
  if (!timeStr) return '未知'
  const diffSec = Math.abs(dayjs().diff(dayjs(timeStr), 'second'))
  if (diffSec < 15) return '刚刚'
  return dayjs(timeStr).fromNow()
}

async function fetchData() {
  loading.value = true
  try {
    await Promise.all([
      api.dashboard().then(data => { stats.value = data }).catch(e => message.error(e.message)),
      Promise.all([api.listWorkers(), api.listDastWorkers()]).then(([sastWorkers, dastWorkers]) => {
        workers.value = [
          ...sastWorkers.map((status): DashboardWorker => ({ kind: 'SAST', status })),
          ...dastWorkers.map((status): DashboardWorker => ({ kind: 'DAST', status })),
        ]
      }),
    ])
  } catch (e: any) {
    message.error(e.message || '加载仪表盘数据失败')
  } finally {
    loading.value = false
  }
}

onMounted(fetchData)
</script>
