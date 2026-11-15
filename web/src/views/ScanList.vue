<template>
  <div class="h-full flex flex-col overflow-hidden gap-4">
    <!-- 顶部操作栏（固定） -->
    <div class="bg-white rounded-xl border border-slate-200/80 p-5 shadow-2xs flex items-center justify-between shrink-0">
      <div>
        <h1 class="text-base font-bold text-slate-800 flex items-center gap-2">
          <Code2 class="w-4 h-4 text-blue-500" />
          <span>SAST 静态扫描任务列表</span>
        </h1>
        <p class="text-xs text-slate-400 mt-1">上传源码 ZIP 压缩包，自动创建审计记录并触发 CodeQL 静态深度分析</p>
      </div>
      <div class="flex items-center gap-3">
        <a-button size="middle" :loading="loading" @click="load">
          <template #icon><RotateCw class="w-3.5 h-3.5 inline-block mr-1" /></template>
          刷新
        </a-button>
        <a-button type="primary" size="middle" @click="showCreate = true">
          <template #icon><Plus class="w-3.5 h-3.5 inline-block mr-1" /></template>
          上传源码并扫描
        </a-button>
      </div>
    </div>

    <!-- 任务列表卡片（卡片内独立滚动） -->
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
            <span class="font-mono font-semibold text-xs text-slate-600">#{{ record.id }}</span>
          </template>
          <template v-else-if="column.key === 'repo_url'">
            <div class="flex items-center gap-2">
              <FileArchive class="w-4 h-4 text-amber-500 shrink-0" />
              <a-tooltip :title="record.repo_url">
                <span
                  class="font-mono text-xs text-slate-800 font-medium max-w-xs truncate cursor-pointer hover:text-blue-600"
                  @click="router.push(`/sast/scans/${record.id}`)"
                >
                  {{ record.repo_url }}
                </span>
              </a-tooltip>
            </div>
          </template>
          <template v-else-if="column.key === 'language'">
            <span class="px-2 py-0.5 rounded text-xs font-medium bg-slate-100 text-slate-700">
              {{ record.language || '—' }}
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
          <template v-else-if="column.key === 'worker_id'">
            <span class="font-mono text-xs text-slate-500">{{ record.worker_id || '等待调度' }}</span>
          </template>
          <template v-else-if="column.key === 'created_at'">
            <span class="text-xs text-slate-500 font-mono">{{ dayjs(record.created_at).format('YYYY-MM-DD HH:mm:ss') }}</span>
          </template>
          <template v-else-if="column.key === 'timeout'">
            <span class="text-xs text-slate-500 font-mono">{{ fmtDuration(record.timeout) }}</span>
          </template>
          <template v-else-if="column.key === 'action'">
            <a-popconfirm
              title="确定要删除此任务及关联漏洞报告吗？"
              ok-text="确认删除"
              cancel-text="取消"
              ok-type="danger"
              @confirm="handleDeleteScan(record.id)"
            >
              <a-button type="link" danger size="small">
                删除
              </a-button>
            </a-popconfirm>
          </template>
        </template>
      </a-table>
      </div>
    </div>

    <!-- 上传源码并创建扫描任务弹窗 -->
    <a-modal v-model:open="showCreate" title="上传源码 ZIP 发起 SAST 扫描" :confirm-loading="creating" @ok="submitCreate">
      <a-form :model="form" layout="vertical" class="mt-4">
        <a-form-item label="源码 ZIP 压缩包 (.zip)" required>
          <a-upload-dragger
            name="file"
            :multiple="false"
            :before-upload="beforeUpload"
            :file-list="fileList"
            @remove="handleRemove"
            accept=".zip"
          >
            <p class="ant-upload-drag-icon">
              <UploadCloud class="w-8 h-8 mx-auto text-blue-500 mb-2" />
            </p>
            <p class="ant-upload-text text-xs font-medium text-slate-700">点击或将源码 .zip 文件拖拽到此处</p>
            <p class="ant-upload-hint text-[11px] text-slate-400">仅接收包含代码工程的 .zip 压缩包</p>
          </a-upload-dragger>
        </a-form-item>
        <a-form-item label="目标分析语言" required>
          <a-select v-model:value="form.language" placeholder="选择编程语言">
            <a-select-option value="go">Go (Golang)</a-select-option>
            <a-select-option value="java">Java / Kotlin</a-select-option>
            <a-select-option value="python">Python</a-select-option>
            <a-select-option value="javascript">JavaScript / TypeScript</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="任务超时时限（秒）">
          <a-input-number v-model:value="form.timeout" :min="60" :max="7200" class="w-full" />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import type { UploadProps } from 'ant-design-vue'
import dayjs from 'dayjs'
import {
  Code2,
  Plus,
  RotateCw,
  FileArchive,
  UploadCloud,
} from 'lucide-vue-next'
import { api } from '@/api'
import type { Scan } from '@/types'

const router = useRouter()
const scans = ref<Scan[]>([])
const loading = ref(false)
const showCreate = ref(false)
const creating = ref(false)

const form = ref({ language: 'go', timeout: 600 })
const fileList = ref<any[]>([])
const selectedFile = ref<File | null>(null)

const columns = [
  { title: 'ID', dataIndex: 'id', key: 'id', width: 70 },
  { title: '压缩包', dataIndex: 'repo_url', key: 'repo_url' },
  { title: '语言', dataIndex: 'language', key: 'language', width: 120 },
  { title: '状态', dataIndex: 'status', key: 'status', width: 120, align: 'center' as const },
  { title: '执行 Worker', dataIndex: 'worker_id', key: 'worker_id', width: 180 },
  { title: '超时配置', dataIndex: 'timeout', key: 'timeout', width: 110 },
  { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 170 },
  { title: '操作', key: 'action', width: 90, align: 'center' as const },
]

const beforeUpload: UploadProps['beforeUpload'] = (file) => {
  if (!file.name.endsWith('.zip')) {
    message.error('只支持上传 .zip 格式的源码压缩包')
    return false
  }
  selectedFile.value = file
  fileList.value = [file]
  return false
}

const handleRemove: UploadProps['onRemove'] = () => {
  selectedFile.value = null
  fileList.value = []
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

function fmtDuration(ns: number) {
  const s = Math.round(ns / 1e9)
  return s >= 60 ? `${Math.floor(s / 60)}分${s % 60}秒` : `${s}秒`
}

async function load() {
  loading.value = true
  try {
    scans.value = await api.listScans()
  } catch (e: any) {
    message.error(e.message)
  } finally {
    loading.value = false
  }
}

async function handleDeleteScan(id: number) {
  try {
    await api.deleteScan(id)
    message.success(`扫描任务 #${id} 已成功删除`)
    await load()
  } catch (e: any) {
    message.error(e.message || '删除任务失败')
  }
}

async function submitCreate() {
  if (!selectedFile.value) {
    message.warning('请选择要上传的源码 .zip 压缩包')
    return
  }
  creating.value = true
  try {
    const scan = await api.createScan({
      file: selectedFile.value,
      language: form.value.language,
      timeout: form.value.timeout,
    })
    message.success(`任务 #${scan.id} 创建成功，源码已投递至扫描队列`)
    showCreate.value = false
    selectedFile.value = null
    fileList.value = []
    form.value = { language: 'go', timeout: 600 }
    await load()
  } catch (e: any) {
    message.error(e.message)
  } finally {
    creating.value = false
  }
}

onMounted(load)
</script>
