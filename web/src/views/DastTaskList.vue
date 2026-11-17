<template>
  <div class="h-full flex flex-col overflow-hidden gap-4">
    <!-- 顶部操作栏（固定） -->
    <div class="bg-white rounded-xl border border-slate-200/80 p-5 shadow-2xs flex items-center justify-between shrink-0">
      <div>
        <h1 class="text-base font-bold text-slate-800 flex items-center gap-2">
          <Crosshair class="w-4 h-4 text-blue-500" />
          <span>DAST 扫描批次列表</span>
        </h1>
        <p class="text-xs text-slate-400 mt-1">按资产维度发起的动态扫描批次，点击查看任务进度与漏洞</p>
      </div>
      <div class="flex items-center gap-3">
        <a-button size="middle" :loading="loading" @click="load">
          <template #icon><RotateCw class="w-3.5 h-3.5 inline-block mr-1" /></template>
          刷新
        </a-button>
      </div>
    </div>

    <!-- 批次列表卡片（卡片内独立滚动） -->
    <div class="bg-white rounded-xl border border-slate-200/80 p-5 shadow-2xs flex-1 min-h-0 overflow-hidden flex flex-col">
      <div class="flex-1 overflow-y-auto">
        <a-table
          :columns="columns"
          :data-source="scans"
          :loading="loading"
          row-key="id"
          size="middle"
          :pagination="{ pageSize: 15, showSizeChanger: false }"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'id'">
              <span
                class="font-mono font-semibold text-xs text-blue-600 cursor-pointer hover:underline"
                @click="router.push(`/dast/tasks/${record.id}`)"
              >
                #{{ record.id }}
              </span>
            </template>
            <template v-else-if="column.key === 'created_by'">
              <span class="text-xs text-slate-600">{{ record.created_by || '—' }}</span>
            </template>
            <template v-else-if="column.key === 'progress'">
              <div class="flex items-center gap-2">
                <a-progress
                  :percent="progress(record as DastScan)"
                  size="small"
                  :show-info="false"
                  class="!w-24"
                  :status="record.status === 'failed' ? 'exception' : undefined"
                />
                <span class="font-mono text-xs text-slate-500">
                  {{ record.finished_tasks }}/{{ record.total_tasks }}
                </span>
              </div>
            </template>
            <template v-else-if="column.key === 'failed_tasks'">
              <span class="font-mono text-xs" :class="record.failed_tasks > 0 ? 'text-rose-600' : 'text-slate-400'">
                {{ record.failed_tasks }}
              </span>
            </template>
            <template v-else-if="column.key === 'status'">
              <span
                class="px-2.5 py-0.5 rounded-full text-xs font-medium inline-flex items-center gap-1.5"
                :class="statusBadgeStyle(record.status)"
              >
                <span class="w-1.5 h-1.5 rounded-full" :class="statusDotStyle(record.status)"></span>
                {{ statusText(record.status) }}
              </span>
            </template>
            <template v-else-if="column.key === 'created_at'">
              <span class="text-xs text-slate-500 font-mono">{{ dayjs(record.created_at).format('YYYY-MM-DD HH:mm:ss') }}</span>
            </template>
            <template v-else-if="column.key === 'finished_at'">
              <span class="text-xs text-slate-500 font-mono">
                {{ record.finished_at ? dayjs(record.finished_at).format('YYYY-MM-DD HH:mm:ss') : '—' }}
              </span>
            </template>
          </template>
        </a-table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import dayjs from 'dayjs'
import { Crosshair, RotateCw } from 'lucide-vue-next'
import { api } from '@/api'
import type { DastScan } from '@/types'

const router = useRouter()
const scans = ref<DastScan[]>([])
const loading = ref(false)

const columns = [
  { title: '批次 ID', dataIndex: 'id', key: 'id', width: 100 },
  { title: '发起人', dataIndex: 'created_by', key: 'created_by', width: 140 },
  { title: '进度', key: 'progress', width: 200 },
  { title: '失败任务', dataIndex: 'failed_tasks', key: 'failed_tasks', width: 100, align: 'center' as const },
  { title: '状态', dataIndex: 'status', key: 'status', width: 120, align: 'center' as const },
  { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 170 },
  { title: '结束时间', dataIndex: 'finished_at', key: 'finished_at', width: 170 },
]

function progress(scan: DastScan) {
  if (scan.total_tasks === 0) return 0
  return Math.round((scan.finished_tasks / scan.total_tasks) * 100)
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
      success: '扫描成功',
      failed: '扫描失败',
    }[status] ?? status
  )
}

async function load() {
  loading.value = true
  try {
    scans.value = await api.listDastScans()
  } catch (e: any) {
    message.error(e.message)
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>
