<template>
  <div class="h-full flex flex-col overflow-hidden gap-4">
    <!-- 顶部操作栏（固定） -->
    <div class="bg-white rounded-xl border border-slate-200/80 p-5 shadow-2xs flex items-center justify-between shrink-0">
      <div>
        <h1 class="text-base font-bold text-slate-800 flex items-center gap-2">
          <Crosshair class="w-4 h-4 text-blue-500" />
          <span>DAST 资产列表</span>
        </h1>
        <p class="text-xs text-slate-400 mt-1">来自 CMDB／SIEM 的资产清单，勾选后按模板与探测端口发起动态扫描</p>
      </div>
      <div class="flex items-center gap-3">
        <a-button size="middle" :loading="loading" @click="load">
          <template #icon><RotateCw class="w-3.5 h-3.5 inline-block mr-1" /></template>
          刷新
        </a-button>
        <a-button type="primary" size="middle" :disabled="selected.length === 0" @click="showCreate = true">
          <template #icon><Plus class="w-3.5 h-3.5 inline-block mr-1" /></template>
          发起扫描（{{ selected.length }}）
        </a-button>
      </div>
    </div>

    <!-- 过滤条（固定） -->
    <div class="bg-white rounded-xl border border-slate-200/80 px-5 py-3 shadow-2xs flex items-end gap-3 shrink-0">
      <div class="w-44">
        <div class="text-[11px] text-slate-400 mb-1">来源标识</div>
        <a-input v-model:value="filter.source_id" size="small" placeholder="source_id" allow-clear />
      </div>
      <div class="w-44">
        <div class="text-[11px] text-slate-400 mb-1">集群</div>
        <a-input v-model:value="filter.cluster_id" size="small" placeholder="cluster_id" allow-clear />
      </div>
      <div class="w-44">
        <div class="text-[11px] text-slate-400 mb-1">网络区域</div>
        <a-input v-model:value="filter.network_zone" size="small" placeholder="network_zone" allow-clear />
      </div>
      <div class="w-44">
        <div class="text-[11px] text-slate-400 mb-1">业务</div>
        <a-input v-model:value="filter.business_id" size="small" placeholder="business_id" allow-clear />
      </div>
      <a-button size="small" type="primary" :loading="loading" @click="load">查询</a-button>
    </div>

    <!-- 资产列表卡片（卡片内独立滚动） -->
    <div class="bg-white rounded-xl border border-slate-200/80 p-5 shadow-2xs flex-1 min-h-0 overflow-hidden flex flex-col">
      <div class="flex-1 overflow-y-auto">
        <a-table
          :columns="columns"
          :data-source="assets"
          :loading="loading"
          :row-selection="rowSelection"
          row-key="cmdb_id"
          size="middle"
          :pagination="{ pageSize: 15, showSizeChanger: false }"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'cmdb_id'">
              <span class="font-mono font-semibold text-xs text-slate-700">{{ record.cmdb_id }}</span>
            </template>
            <template v-else-if="column.key === 'host'">
              <span class="font-mono text-xs text-slate-800">{{ record.host }}</span>
            </template>
            <template v-else-if="column.key === 'registered_services'">
              <span v-if="record.registered_services.length === 0" class="text-xs text-slate-300">无登记服务</span>
              <a-space v-else :size="4" wrap>
                <a-tag
                  v-for="svc in record.registered_services"
                  :key="`${svc.endpoint.host}:${svc.endpoint.port}/${svc.endpoint.transport}`"
                  color="blue"
                  class="!text-[10px] !font-mono !mr-0"
                >
                  {{ svc.application_protocol || 'unknown' }}
                  {{ svc.endpoint.host }}:{{ svc.endpoint.port }}/{{ svc.endpoint.transport }}
                </a-tag>
              </a-space>
            </template>
            <template v-else-if="column.key === 'scope'">
              <span class="text-xs text-slate-600">{{ record.cluster_id }} / {{ record.network_zone }}</span>
            </template>
            <template v-else-if="column.key === 'owner'">
              <span class="text-xs text-slate-600">{{ record.owner || '—' }}</span>
            </template>
          </template>
          <template #emptyText>
            <div class="py-12 text-center text-xs text-slate-400">
              {{ emptyText }}
            </div>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 发起扫描弹窗 -->
    <a-modal
      v-model:open="showCreate"
      title="发起 DAST 动态扫描"
      width="640px"
      :confirm-loading="creating"
      ok-text="创建扫描"
      cancel-text="取消"
      @ok="submitCreate"
    >
      <a-form :model="form" layout="vertical" class="mt-4">
        <a-form-item label="请求幂等键" required>
          <a-input v-model:value="form.request_key" placeholder="同一键重复提交返回同一批次" />
        </a-form-item>
        <div class="grid grid-cols-2 gap-4">
          <a-form-item label="模板版本" required>
            <a-input v-model:value="form.template_version" placeholder="与模板目录 catalog.json 的版本一致" />
          </a-form-item>
          <a-form-item label="超时时限（秒）" required>
            <a-input-number v-model:value="form.timeout_seconds" :min="60" :max="86400" class="w-full" />
          </a-form-item>
          <a-form-item label="速率上限（每秒请求）" required>
            <a-input-number v-model:value="form.rate_limit" :min="1" :max="5000" class="w-full" />
          </a-form-item>
          <a-form-item label="PoC 并发数" required>
            <a-input-number v-model:value="form.concurrency" :min="1" :max="100" class="w-full" />
          </a-form-item>
        </div>
        <a-form-item label="模板 ID" required>
          <a-select
            v-model:value="form.template_ids"
            mode="tags"
            placeholder="输入模板 ID 后回车，例如 http-cve-2024-0001"
          />
        </a-form-item>
        <a-form-item label="探测端口" required>
          <div class="w-full">
            <div
              v-for="(p, idx) in form.probe_ports"
              :key="idx"
              class="flex items-center gap-2 mb-2"
            >
              <a-input-number v-model:value="p.port" :min="1" :max="65535" placeholder="端口" class="w-40" />
              <a-select v-model:value="p.transport" class="w-32">
                <a-select-option value="tcp">tcp</a-select-option>
                <a-select-option value="udp">udp</a-select-option>
              </a-select>
              <a-button size="small" danger @click="form.probe_ports.splice(idx, 1)">删除</a-button>
            </div>
            <a-button size="small" @click="form.probe_ports.push({ port: 443, transport: 'tcp' })">添加端口</a-button>
          </div>
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { Crosshair, Plus, RotateCw } from 'lucide-vue-next'
import { api } from '@/api'
import type { DastAsset, DastAssetFilter, DastPortSpec } from '@/types'

const router = useRouter()
const assets = ref<DastAsset[]>([])
const loading = ref(false)
const creating = ref(false)
const showCreate = ref(false)
const selectedKeys = ref<string[]>([])
const sourceNotConfigured = ref(false)

const filter = reactive<DastAssetFilter>({
  source_id: '',
  cluster_id: '',
  network_zone: '',
  business_id: '',
})

const form = reactive({
  request_key: '',
  template_version: '',
  template_ids: [] as string[],
  rate_limit: 100,
  concurrency: 10,
  timeout_seconds: 600,
  probe_ports: [{ port: 443, transport: 'tcp' }] as DastPortSpec[],
})

const columns = [
  { title: '资产 ID', dataIndex: 'cmdb_id', key: 'cmdb_id', width: 140 },
  { title: '主机地址', dataIndex: 'host', key: 'host', width: 180 },
  { title: '来源', dataIndex: 'source_id', key: 'source_id', width: 120 },
  { title: '集群 / 区域', key: 'scope', width: 200 },
  { title: '登记服务', key: 'registered_services' },
  { title: '负责人', dataIndex: 'owner', key: 'owner', width: 120 },
]

const rowSelection = computed(() => ({
  selectedRowKeys: selectedKeys.value,
  onChange: (keys: (string | number)[]) => {
    selectedKeys.value = keys.map(String)
  },
}))

const selected = computed(() => assets.value.filter((a) => selectedKeys.value.includes(a.cmdb_id)))

const emptyText = computed(() =>
  sourceNotConfigured.value
    ? '资产来源尚未接入：server 未配置 CMDB／SIEM 适配器'
    : '当前筛选范围内没有资产',
)

async function load() {
  loading.value = true
  sourceNotConfigured.value = false
  try {
    assets.value = await api.listDastAssets({
      source_id: filter.source_id || undefined,
      cluster_id: filter.cluster_id || undefined,
      network_zone: filter.network_zone || undefined,
      business_id: filter.business_id || undefined,
    })
  } catch (e: any) {
    if (String(e.message).includes('asset source')) {
      sourceNotConfigured.value = true
      assets.value = []
    } else {
      message.error(e.message)
    }
  } finally {
    loading.value = false
  }
}

async function submitCreate() {
  if (!form.request_key.trim()) {
    message.warning('请填写请求幂等键')
    return
  }
  if (!form.template_version.trim() || form.template_ids.length === 0) {
    message.warning('请填写模板版本和至少一个模板 ID')
    return
  }
  if (form.probe_ports.length === 0) {
    message.warning('请至少配置一个探测端口')
    return
  }
  creating.value = true
  try {
    const scan = await api.createDastScan({
      request_key: form.request_key.trim(),
      assets: selected.value.map((a) => ({ source_id: a.source_id, cmdb_id: a.cmdb_id })),
      filter: {
        source_id: filter.source_id || undefined,
        cluster_id: filter.cluster_id || undefined,
        network_zone: filter.network_zone || undefined,
        business_id: filter.business_id || undefined,
      },
      options: {
        template_version: form.template_version.trim(),
        template_ids: form.template_ids,
        rate_limit: form.rate_limit,
        concurrency: form.concurrency,
        timeout_seconds: form.timeout_seconds,
        probe_ports: form.probe_ports,
      },
    })
    message.success(`批次 #${scan.id} 已创建，任务已进入执行队列`)
    showCreate.value = false
    selectedKeys.value = []
    router.push(`/dast/tasks/${scan.id}`)
  } catch (e: any) {
    message.error(e.message)
  } finally {
    creating.value = false
  }
}

onMounted(load)
</script>
