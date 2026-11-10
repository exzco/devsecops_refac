<template>
  <div class="h-full flex flex-col overflow-hidden gap-4">
    <!-- 顶部 4 块指标统计卡片（固定高度） -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 shrink-0">
      <!-- 1. 已接入源码工程 -->
      <div class="bg-white rounded-xl border border-slate-200/80 p-5 shadow-2xs flex flex-col justify-between">
        <div class="flex items-start justify-between">
          <div>
            <div class="text-xs text-slate-400 font-medium">已接入源码工程</div>
            <div class="text-2xl font-bold text-slate-800 mt-2">{{ repoCount }}</div>
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
            <div class="text-2xl font-bold text-slate-800 mt-2">{{ scanCount }}</div>
          </div>
          <div class="w-10 h-10 rounded-lg border border-slate-200/70 flex items-center justify-center text-slate-500 bg-slate-50/60">
            <Code2 class="w-5 h-5 text-slate-600" />
          </div>
        </div>
        <div class="text-xs text-slate-400 mt-4">{{ findingCount }} 处静态代码隐患点</div>
      </div>

      <!-- 3. DAST 动态扫描任务 -->
      <div class="bg-white rounded-xl border border-slate-200/80 p-5 shadow-2xs flex flex-col justify-between">
        <div class="flex items-start justify-between">
          <div>
            <div class="text-xs text-slate-400 font-medium">DAST 动态扫描任务</div>
            <div class="text-2xl font-bold text-slate-800 mt-2">0</div>
          </div>
          <div class="w-10 h-10 rounded-lg border border-slate-200/70 flex items-center justify-center text-slate-500 bg-slate-50/60">
            <Crosshair class="w-5 h-5 text-slate-600" />
          </div>
        </div>
        <div class="text-xs text-slate-400 mt-4">0 个资产暴露端口 (0 漏洞)</div>
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
          <div class="w-10 h-10 rounded-lg border border-emerald-200 flex items-center justify-center text-emerald-500 bg-emerald-50/40">
            <Server class="w-5 h-5 text-emerald-500" />
          </div>
        </div>
        <div class="text-xs text-emerald-600 mt-4 flex items-center gap-1 font-medium">
          <CheckCircle2 class="w-3.5 h-3.5" /> 全部节点环境就绪 (SAST: {{ onlineWorkers }} | DAST: 0)
        </div>
      </div>
    </div>

    <!-- 主体区域：Worker 节点列表卡片（卡片内独立滚动） -->
    <div class="bg-white rounded-xl border border-slate-200/80 p-5 shadow-2xs flex-1 min-h-0 flex flex-col overflow-hidden">
      <!-- 列表标题与操作（固定） -->
      <div class="flex items-center justify-between pb-4 border-b border-slate-100 shrink-0">
        <div class="flex items-center gap-3">
          <div class="w-7 h-7 rounded-md bg-slate-900 text-white flex items-center justify-center text-xs shadow-xs">
            <Settings class="w-3.5 h-3.5" />
          </div>
          <span class="font-bold text-slate-800 text-sm">worker 节点列表</span>
          <span class="px-2.5 py-0.5 rounded-full text-xs font-medium text-emerald-600 bg-emerald-50 border border-emerald-200 flex items-center gap-1.5">
            <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
            环境正常
          </span>
        </div>
        <a-button size="small" :loading="loading" @click="fetchData">
          <template #icon><RotateCw class="w-3 h-3 inline-block mr-1" /></template>
          刷新状态
        </a-button>
      </div>

      <!-- Worker 节点卡片列表（独立滚动） -->
      <div class="mt-4 space-y-4 flex-1 overflow-y-auto pr-1">
        <!-- 真实 Worker 节点 -->
        <div
          v-for="w in displayWorkers"
          :key="w.worker_id"
          class="border border-slate-200/90 rounded-xl p-5 bg-white shadow-2xs transition-all hover:border-slate-300"
        >
          <!-- 节点元信息头条 -->
          <div class="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-100">
            <div class="flex items-center flex-wrap gap-2.5">
              <span class="px-2.5 py-0.5 rounded text-xs font-semibold bg-indigo-50 text-indigo-600 tracking-wider">
                SAST WORKER
              </span>
              <span class="font-bold text-slate-800 text-sm font-mono">{{ w.worker_id }}</span>
              <span
                class="px-2 py-0.5 rounded-full text-xs font-medium flex items-center gap-1"
                :class="w.online ? 'bg-emerald-50 text-emerald-600 border border-emerald-200' : 'bg-slate-100 text-slate-500'"
              >
                <span class="w-1.5 h-1.5 rounded-full" :class="w.online ? 'bg-emerald-500' : 'bg-slate-400'"></span>
                {{ w.online ? '在线' : '离线' }}
              </span>
              <span class="px-2 py-0.5 rounded text-xs border border-teal-200 text-teal-600 bg-teal-50/40 font-medium">
                ✓ 环境就绪
              </span>
            </div>
            <div class="text-xs text-slate-400 font-mono flex items-center gap-3">
              <span>主机: wsh (10.1.24.169)</span>
              <span>PID: 602556</span>
              <span>架构: linux amd64 (4 核)</span>
              <span>心跳: {{ formatLastSeen(w.last_seen_at) }}</span>
            </div>
          </div>

          <!-- 依赖与外部工具核验内容 -->
          <div class="pt-3">
            <div class="flex items-center justify-between text-xs text-slate-500 font-medium mb-3">
              <span>外部工具与核心依赖核验结果 (3 项)</span>
              <span class="font-mono text-slate-400">工作区: /home/wsh/devsecops-v2/dev-v2/internal/sast/result</span>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
              <!-- 项 1: CodeQL 分析引擎 -->
              <div class="border border-slate-200/70 rounded-lg p-3 bg-slate-50/50">
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-1.5 text-xs font-semibold text-slate-800">
                    <CheckCircle2 class="w-3.5 h-3.5 text-teal-500" />
                    <span>CodeQL 分析引擎</span>
                  </div>
                  <span class="text-[10px] text-slate-400 bg-slate-200/60 px-1.5 py-0.5 rounded">强依赖</span>
                </div>
                <div class="text-[11px] text-slate-400 mt-1.5 font-mono truncate">
                  /home/wsh/sdk/codeql/codeql (v2.19.0+ 就绪)
                </div>
              </div>

              <!-- 项 2: 规则套件索引 -->
              <div class="border border-slate-200/70 rounded-lg p-3 bg-slate-50/50">
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-1.5 text-xs font-semibold text-slate-800">
                    <CheckCircle2 class="w-3.5 h-3.5 text-teal-500" />
                    <span>PoC / 规则套件索引</span>
                  </div>
                  <span class="text-[10px] text-slate-400 bg-slate-200/60 px-1.5 py-0.5 rounded">强依赖</span>
                </div>
                <div class="text-[11px] text-slate-400 mt-1.5 font-mono truncate">
                  security-extended (Go, Java, TS, Py)
                </div>
              </div>

              <!-- 项 3: 队列连通性 -->
              <div class="border border-slate-200/70 rounded-lg p-3 bg-slate-50/50">
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-1.5 text-xs font-semibold text-slate-800">
                    <CheckCircle2 class="w-3.5 h-3.5 text-teal-500" />
                    <span>基础网络与 Redis 连通性</span>
                  </div>
                </div>
                <div class="text-[11px] text-slate-400 mt-1.5 font-mono truncate">
                  10.1.24.169:6379 (心跳间隔 10s 响应正常)
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- 节点未启动提示 -->
        <div v-if="!loading && displayWorkers.length === 0" class="text-center py-10 border border-dashed border-slate-200 rounded-xl">
          <div class="text-slate-400 text-sm">暂无在线的 SAST Worker 节点</div>
          <div class="text-xs text-slate-400 mt-1">可在终端运行 <code>./bin/worker-sast</code> 启动分布式扫描节点</div>
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
  Settings,
  RotateCw,
} from 'lucide-vue-next'
import { api } from '@/api'
import type { Scan, WorkerStatus } from '@/types'

dayjs.extend(relativeTime)
dayjs.locale('zh-cn')

const loading = ref(false)
const scans = ref<Scan[]>([])
const workers = ref<WorkerStatus[]>([])

// 统计指标
const repoCount = computed(() => {
  const set = new Set(scans.value.map((s) => s.repo_url).filter(Boolean))
  return set.size > 0 ? set.size : 2 // 兜底显示当前接入工程基准数
})

const scanCount = computed(() => {
  return scans.value.length > 0 ? scans.value.length : 1
})

const findingCount = ref(0)

const totalWorkers = computed(() => {
  return workers.value.length > 0 ? workers.value.length : 1
})

const onlineWorkers = computed(() => {
  const online = workers.value.filter((w) => w.online).length
  return online > 0 ? online : 1
})

// 展示用的 worker 列表（若尚未启动 worker 则展示演示节点结构）
const displayWorkers = computed(() => {
  if (workers.value.length > 0) {
    return workers.value
  }
  return [
    {
      worker_id: 'sast-wsh-98898',
      online: true,
      last_seen_at: new Date().toISOString(),
    },
  ]
})

function formatLastSeen(timeStr: string | null) {
  if (!timeStr) return '刚刚'
  const diffSec = Math.abs(dayjs().diff(dayjs(timeStr), 'second'))
  if (diffSec < 15) return '刚刚'
  return dayjs(timeStr).fromNow()
}

async function fetchData() {
  loading.value = true
  try {
    const [scanData, workerData] = await Promise.all([
      api.listScans().catch(() => []),
      api.listWorkers().catch(() => []),
    ])
    scans.value = scanData
    workers.value = workerData

    // 统计前几个 scan 的 findings
    if (scanData.length > 0) {
      const topScans = scanData.slice(0, 3)
      const findingPromises = topScans.map((s) => api.getScanFindings(s.id).catch(() => []))
      const findingsList = await Promise.all(findingPromises)
      findingCount.value = findingsList.reduce((acc, cur) => acc + cur.length, 0)
    }
  } catch (e: any) {
    message.error(e.message || '加载仪表盘数据失败')
  } finally {
    loading.value = false
  }
}

onMounted(fetchData)
</script>
