<template>
  <div class="h-full flex flex-col overflow-hidden gap-3">
    <!-- 顶部紧凑信息条（固定无滚动） -->
    <div class="bg-white rounded-xl border border-slate-200/80 px-4 py-2.5 shadow-2xs flex items-center justify-between shrink-0">
      <div class="flex items-center gap-3">
        <a-button size="small" @click="router.push('/sast/scans')">
          <template #icon><ArrowLeft class="w-3.5 h-3.5 inline-block mr-1" /></template>
          返回任务列表
        </a-button>
        <div class="h-4 w-px bg-slate-200"></div>
        <div class="flex items-center gap-2">
          <span class="text-xs font-bold text-slate-800">SAST 扫描任务 #{{ id }}</span>
          <span
            v-if="scan"
            class="px-2 py-0.5 rounded-full text-xs font-medium inline-flex items-center gap-1.5"
            :class="statusBadgeStyle(scan.status)"
          >
            <span class="w-1.5 h-1.5 rounded-full" :class="statusDotStyle(scan.status)"></span>
            {{ statusText(scan.status) }}
          </span>
        </div>
        <div v-if="scan" class="hidden md:flex items-center gap-2 text-xs text-slate-400 font-mono">
          <span class="bg-slate-100 px-2 py-0.5 rounded text-slate-600">{{ scan.language }}</span>
          <span>Commit: {{ scan.commit_sha ? scan.commit_sha.slice(0, 8) : '—' }}</span>
          <span>Worker: {{ scan.worker_id || '等待调度' }}</span>
        </div>
      </div>

      <div class="flex items-center gap-3">
        <span class="text-xs text-slate-500 font-medium">
          发现 <strong class="text-rose-600 font-bold">{{ findings.length }}</strong> 处隐患
        </span>
        <a-button size="small" :loading="loading" @click="refreshAll">
          <template #icon><RotateCw class="w-3 h-3 inline-block mr-1" /></template>
          刷新
        </a-button>
        <a-popconfirm
          title="确定要删除当前扫描任务及全部漏洞记录吗？"
          ok-text="确认删除"
          cancel-text="取消"
          ok-type="danger"
          @confirm="handleDeleteCurrentScan"
        >
          <a-button size="small" danger :loading="deleting">
            <template #icon><Trash2 class="w-3 h-3 inline-block mr-1" /></template>
            删除任务
          </a-button>
        </a-popconfirm>
      </div>
    </div>

    <!-- 主体区域：三分区布局 (无整体页面滚动栏，各卡片独立滚动) -->
    <div class="flex-1 min-h-0 flex gap-3 overflow-hidden">
      <!-- 1. 左侧：垂直漏洞列表卡片 -->
      <div class="w-80 lg:w-96 shrink-0 flex flex-col bg-white rounded-xl border border-slate-200/80 shadow-2xs overflow-hidden">
        <!-- 列表头与过滤（固定） -->
        <div class="p-3 border-b border-slate-100 shrink-0">
          <!-- 严重度分段过滤按钮 -->
          <div class="grid grid-cols-4 gap-1 text-[11px]">
            <button
              @click="filterLevel = ''"
              class="py-1.5 px-1.5 rounded text-center font-medium transition-colors cursor-pointer"
              :class="filterLevel === '' ? 'bg-slate-900 text-white' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'"
            >
              全部 ({{ findings.length }})
            </button>
            <button
              @click="filterLevel = 'error'"
              class="py-1.5 px-1.5 rounded text-center font-medium transition-colors cursor-pointer"
              :class="filterLevel === 'error' ? 'bg-rose-600 text-white' : 'bg-rose-50 text-rose-600 hover:bg-rose-100'"
            >
              高危 ({{ countByLevel('error') }})
            </button>
            <button
              @click="filterLevel = 'warning'"
              class="py-1.5 px-1.5 rounded text-center font-medium transition-colors cursor-pointer"
              :class="filterLevel === 'warning' ? 'bg-amber-600 text-white' : 'bg-amber-50 text-amber-700 hover:bg-amber-100'"
            >
              中危 ({{ countByLevel('warning') }})
            </button>
            <button
              @click="filterLevel = 'note'"
              class="py-1.5 px-1.5 rounded text-center font-medium transition-colors cursor-pointer"
              :class="filterLevel === 'note' ? 'bg-blue-600 text-white' : 'bg-blue-50 text-blue-600 hover:bg-blue-100'"
            >
              低危 ({{ countByLevel('note') }})
            </button>
          </div>
        </div>

        <!-- 漏洞纵向列表（卡片内独立滚动） -->
        <div class="flex-1 overflow-y-auto p-2 space-y-1.5 divide-y-0">
          <a-spin :spinning="loading && !scan">
            <template v-if="filteredFindings.length > 0">
              <div
                v-for="(f, idx) in filteredFindings"
                :key="f.rule_id + idx"
                @click="selectFinding(idx)"
                class="p-2.5 rounded-lg border transition-all cursor-pointer text-left"
                :class="
                  selectedIndex === idx
                    ? 'bg-blue-50/90 border-blue-400 shadow-xs ring-1 ring-blue-300'
                    : 'bg-white hover:bg-slate-50 border-slate-200/80'
                "
              >
                <!-- 严重度 + 评分 + 污点链标记 -->
                <div class="flex items-center justify-between gap-1 mb-1">
                  <div class="flex items-center gap-1.5">
                    <span
                      class="px-1.5 py-0.2 rounded text-[10px] font-bold uppercase tracking-wider inline-flex items-center gap-1"
                      :class="levelBadgeStyle(f.level)"
                    >
                      <AlertCircle v-if="f.level === 'error'" class="w-3 h-3" />
                      <AlertTriangle v-else-if="f.level === 'warning'" class="w-3 h-3" />
                      <Info v-else class="w-3 h-3" />
                      {{ levelText(f.level) }}
                    </span>
                    <span v-if="f.security_score != null" class="font-mono text-[10px] font-bold text-slate-600">
                      ★ {{ f.security_score.toFixed(1) }}
                    </span>
                  </div>
                  <span
                    v-if="hasFlow(f)"
                    class="text-[10px] px-1.5 py-0.2 rounded bg-indigo-50 text-indigo-600 font-mono flex items-center gap-1"
                  >
                    <Workflow class="w-2.5 h-2.5" />
                    {{ f.code_flows[0].steps.length }} 步污点流
                  </span>
                </div>

                <!-- 规则 ID -->
                <div class="font-mono font-bold text-xs text-slate-800 truncate">
                  {{ f.rule_id }}
                </div>

                <!-- 简短说明 -->
                <div class="text-[11px] text-slate-600 line-clamp-1 mt-0.5">
                  {{ f.title || f.message }}
                </div>

                <!-- 代码位置 -->
                <div class="text-[10px] text-slate-400 font-mono mt-1 flex items-center gap-1 truncate">
                  <FileCode class="w-3 h-3 shrink-0" />
                  <span>{{ formatLocation(f.locations?.[0]) }}</span>
                </div>
              </div>
            </template>
            <div v-else class="py-12 text-center text-xs text-slate-400">
              无匹配的漏洞项
            </div>
          </a-spin>
        </div>
      </div>

      <!-- 右侧垂直两卡片：上为代码上下文，下为污点追踪链条 -->
      <div class="flex-1 min-w-0 flex flex-col gap-3 overflow-hidden">
        <!-- 2. 右侧上部卡片：代码上下文 (Code Context) -->
        <div class="flex-1 min-h-0 bg-white rounded-xl border border-slate-200/80 shadow-2xs flex flex-col overflow-hidden">
          <!-- 上下文头部栏（固定） -->
          <div class="shrink-0 px-4 py-2 bg-slate-50/80 border-b border-slate-100 flex items-center justify-between flex-wrap gap-2">
            <div class="flex items-center gap-2">
              <Code2 class="w-4 h-4 text-blue-500" />
              <span class="font-bold text-xs text-slate-800">代码上下文</span>
              <span
                v-if="displayLocation"
                class="font-mono text-xs font-semibold text-slate-800 bg-white px-2 py-0.5 rounded border border-slate-200/80"
              >
                📄 {{ displayLocation.uri }} : {{ displayLocation.startLine }}
              </span>
              <span
                v-if="activeStepIndex >= 0"
                class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-indigo-100 text-indigo-700"
              >
                污点链节点 #{{ activeStepIndex + 1 }}
              </span>
            </div>

            <!-- 右侧 CWE & 评分 -->
            <div class="flex items-center gap-2">
              <span
                v-for="cwe in activeFinding?.cwes || []"
                :key="cwe"
                class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-50 text-amber-700 border border-amber-200"
              >
                {{ cwe }}
              </span>
            </div>
          </div>

          <!-- 漏洞说明提示条（固定） -->
          <div v-if="activeFinding" class="shrink-0 px-4 py-2 border-b border-slate-100 bg-amber-50/40 text-xs text-slate-700 flex items-start gap-2">
            <AlertCircle class="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
            <div class="leading-relaxed">
              <strong class="font-semibold text-slate-800 mr-1">{{ activeFinding.rule_id }}:</strong>
              {{ activeDescription }}
            </div>
          </div>

          <!-- 代码高亮查看器（卡片内独立滚动） -->
          <div class="flex-1 min-h-0 overflow-y-auto bg-slate-950 p-4 font-mono text-xs leading-relaxed select-text text-slate-200">
            <div v-if="displaySnippetLines.length > 0" class="space-y-0.5">
              <div
                v-for="(line, lineIdx) in displaySnippetLines"
                :key="lineIdx"
                class="flex items-start rounded px-1 transition-colors"
                :class="
                  line.isTarget
                    ? 'bg-rose-950/80 text-rose-200 border-l-2 border-rose-500 font-semibold'
                    : 'hover:bg-slate-900/60 text-slate-300'
                "
              >
                <span class="w-12 text-slate-500 select-none text-right pr-4 font-mono text-[11px]">
                  {{ line.num }}
                </span>
                <span class="flex-1 whitespace-pre-wrap break-all">{{ line.text }}</span>
              </div>
            </div>
            <div v-else class="h-full flex flex-col items-center justify-center text-slate-500 text-xs py-8">
              <FileCode class="w-8 h-8 mb-2 opacity-50" />
            </div>
          </div>
        </div>

        <!-- 3. 右侧下部卡片：污点追踪链条 (Taint Propagation Flow) -->
        <div class="h-60 lg:h-64 shrink-0 bg-white rounded-xl border border-slate-200/80 shadow-2xs flex flex-col overflow-hidden">
          <!-- 链条头部（固定） -->
          <div class="shrink-0 px-4 py-2 bg-slate-50/80 border-b border-slate-100 flex items-center justify-between">
            <div class="flex items-center gap-2">
              <Workflow class="w-4 h-4 text-indigo-500" />
              <span class="font-bold text-xs text-slate-800">污点链标记</span>
              <span class="text-xs text-slate-400 font-mono">
                共 {{ taintSteps.length }} 个数据流节点
              </span>
            </div>
          </div>

          <!-- 污点步骤列表（卡片内独立滚动） -->
          <div class="flex-1 min-h-0 overflow-y-auto p-3 space-y-2 bg-slate-50/30">
            <template v-if="taintSteps.length > 0">
              <div
                v-for="(step, sIdx) in taintSteps"
                :key="sIdx"
                @click="selectStep(sIdx)"
                class="p-2.5 rounded-lg border transition-all cursor-pointer text-xs"
                :class="
                  activeStepIndex === sIdx
                    ? 'border-indigo-400 bg-indigo-50/70 shadow-2xs ring-1 ring-indigo-300'
                    : 'border-slate-200 bg-white hover:bg-slate-50'
                "
              >
                <div class="flex items-center justify-between gap-2 mb-1">
                  <!-- 步骤角色徽标 -->
                  <div class="flex items-center gap-2">
                    <span
                      class="px-2 py-0.5 rounded text-[10px] font-bold font-mono tracking-wider"
                      :class="stepBadgeStyle(sIdx, taintSteps.length)"
                    >
                      {{ stepRoleText(sIdx, taintSteps.length) }}
                    </span>
                    <span class="font-mono text-xs font-semibold text-slate-800">
                      {{ formatLocation(step.location) }}
                    </span>
                  </div>
                  <span class="text-[10px] text-slate-400 font-mono">节点 #{{ sIdx + 1 }}</span>
                </div>

                <div class="text-xs text-slate-600 line-clamp-2">
                  {{ step.message || '数据流参数透传 / 变量引用传递' }}
                </div>

                <!-- 步骤代码简略 -->
                <div
                  v-if="step.location?.snippet"
                  class="mt-1 font-mono text-[11px] text-slate-600 bg-slate-100/80 px-2 py-1 rounded truncate"
                >
                  {{ step.location.snippet.trim() }}
                </div>
              </div>
            </template>

            <!-- 无污点流时的占位说明 -->
            <div v-else class="h-full flex flex-col items-center justify-center text-slate-400 text-xs py-6">
              <Workflow class="w-6 h-6 mb-1 text-slate-300" />
              <span>当前隐患为局部模式匹配规则，未产生跨过程/跨函数的污点流传播链条。</span>
              <span class="text-[11px] text-slate-400 mt-1" v-if="activeFinding?.related_locations?.length">
                关联代码位置数：{{ activeFinding.related_locations.length }} 处
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import {
  ArrowLeft,
  RotateCw,
  Trash2,
  AlertCircle,
  AlertTriangle,
  Info,
  Workflow,
  Code2,
  FileCode,
} from 'lucide-vue-next'
import { api } from '@/api'
import type { Scan, Finding, Location } from '@/types'

const route = useRoute()
const router = useRouter()
const id = computed(() => Number(route.params.id))

const scan = ref<Scan | null>(null)
const loading = ref(false)
const findings = ref<Finding[]>([])
let refreshAll: () => Promise<void>
const deleting = ref(false)

const filterLevel = ref('')
const selectedIndex = ref(0)
const activeStepIndex = ref(-1) // -1 表示查看主缺陷位置，>=0 表示查看污点链某个步骤

const filteredFindings = computed(() => {
  if (!filterLevel.value) return findings.value
  return findings.value.filter((f) => f.level === filterLevel.value)
})

function countByLevel(level: string) {
  return findings.value.filter((f) => f.level === level).length
}

function levelText(level: string) {
  return (
    {
      error: '高危',
      warning: '中危',
      note: '低危',
    }[level] ?? level
  )
}

const activeFinding = computed<Finding | null>(() => {
  if (filteredFindings.value.length === 0) return null
  const idx = Math.min(selectedIndex.value, filteredFindings.value.length - 1)
  return filteredFindings.value[idx] ?? null
})

// 污点链步骤
const taintSteps = computed(() => {
  if (!activeFinding.value) return []
  const flow = activeFinding.value.code_flows?.[0]
  return flow?.steps || []
})

// 当前展示代码位置
const displayLocation = computed<Location | null>(() => {
  if (!activeFinding.value) return null
  if (activeStepIndex.value >= 0 && taintSteps.value[activeStepIndex.value]) {
    return taintSteps.value[activeStepIndex.value].location
  }
  return activeFinding.value.locations?.[0] ?? null
})

// 当前展示的说明文字
const activeDescription = computed(() => {
  if (!activeFinding.value) return ''
  if (activeStepIndex.value >= 0 && taintSteps.value[activeStepIndex.value]) {
    return taintSteps.value[activeStepIndex.value].message || activeFinding.value.message
  }
  return activeFinding.value.message || activeFinding.value.title || '代码安全缺陷'
})

// 代码行渲染辅助
interface CodeLine {
  num: number
  text: string
  isTarget: boolean
}

const displaySnippetLines = computed<CodeLine[]>(() => {
  const loc = displayLocation.value
  if (!loc || !loc.snippet) return []
  const rawLines = loc.snippet.split('\n')
  const startNum = (loc.snippetStartLine && loc.snippetStartLine > 0) ? loc.snippetStartLine : (loc.startLine || 1)
  return rawLines.map((line, i) => {
    const lineNum = startNum + i
    return {
      num: lineNum,
      text: line,
      isTarget: lineNum === loc.startLine || (rawLines.length === 1),
    }
  })
})

function selectFinding(idx: number) {
  selectedIndex.value = idx
  activeStepIndex.value = -1 // 默认切换回主隐患位置
}

function selectStep(sIdx: number) {
  activeStepIndex.value = sIdx
}

function hasFlow(f: Finding) {
  return Boolean(f.code_flows?.[0]?.steps?.length)
}

function formatLocation(loc?: Location) {
  if (!loc) return '—'
  return `${loc.uri}:${loc.startLine}`
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
      running: '正在扫描',
      success: '扫描成功',
      failed: '扫描失败',
    }[status] ?? status
  )
}

function levelBadgeStyle(level: string) {
  return (
    {
      error: 'bg-rose-50 text-rose-600 border border-rose-200',
      warning: 'bg-amber-50 text-amber-700 border border-amber-200',
      note: 'bg-blue-50 text-blue-600 border border-blue-200',
      none: 'bg-slate-100 text-slate-500',
    }[level] ?? 'bg-slate-100 text-slate-500'
  )
}

function stepBadgeStyle(idx: number, total: number) {
  if (idx === 0) return 'bg-emerald-100 text-emerald-700'
  if (idx === total - 1) return 'bg-rose-100 text-rose-700'
  return 'bg-blue-100 text-blue-700'
}

function stepRoleText(idx: number, total: number) {
  if (idx === 0) return '01 源点 Source'
  if (idx === total - 1) return `${String(idx + 1).padStart(2, '0')} 触发 Sink`
  return `${String(idx + 1).padStart(2, '0')} 传递 Pass`
}

function findingKey(f: Finding) {
  return JSON.stringify([f.rule_id, f.fingerprints, f.locations[0]?.uri, f.locations[0]?.startLine, f.locations[0]?.startColumn, f.message])
}

watch(id, (scanID, _, onCleanup) => {
  const detailRequest = new AbortController()
  const { signal } = detailRequest
  let timer: ReturnType<typeof setTimeout>
  onCleanup(() => {
    // 只停止旧详情的读取和轮询，扫描任务由 Worker 执行。
    detailRequest.abort()
    clearTimeout(timer)
  })
  scan.value = null
  findings.value = []
  filterLevel.value = ''
  selectFinding(0)
  loading.value = false
  refreshAll = async () => {
    if (loading.value || signal.aborted) return
    clearTimeout(timer)
    loading.value = true
    try {
      const current = await api.getScan(scanID, signal)
      if (signal.aborted) return
      scan.value = current
      if (current.status === 'success' || current.status === 'failed') {
        const rows = await api.getScanFindings(scanID, signal)
        if (signal.aborted) return
        const key = activeFinding.value && findingKey(activeFinding.value)
        findings.value = rows
        const index = filteredFindings.value.findIndex(f => findingKey(f) === key)
        if (index < 0) selectFinding(0)
        else {
          selectedIndex.value = index
          if (activeStepIndex.value >= taintSteps.value.length) activeStepIndex.value = -1
        }
      }
    } catch (e: any) {
      if (!signal.aborted) message.error(e.message)
    } finally {
      if (!signal.aborted) {
        loading.value = false
        if (scan.value?.status === 'pending' || scan.value?.status === 'running') timer = setTimeout(refreshAll, 3000)
      }
    }
  }
  void refreshAll()
}, { immediate: true })

async function handleDeleteCurrentScan() {
  deleting.value = true
  try {
    const scanID = id.value
    await api.deleteScan(scanID)
    if (scanID !== id.value) return
    message.success(`任务 #${scanID} 已成功删除`)
    router.push('/sast/scans')
  } catch (e: any) {
    message.error(e.message || '删除任务失败')
  } finally {
    deleting.value = false
  }
}

watch(filterLevel, () => {
  selectedIndex.value = 0
  activeStepIndex.value = -1
})

</script>
