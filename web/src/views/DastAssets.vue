<template>
  <div class="h-full flex flex-col overflow-hidden gap-4">
    <!-- 顶部操作栏（固定） -->
    <div class="bg-white rounded-xl border border-slate-200/80 p-5 shadow-2xs flex items-center justify-between shrink-0">
      <div>
        <h1 class="text-base font-bold text-slate-800 flex items-center gap-2">
          <Crosshair class="w-4 h-4 text-blue-500" />
          <span>DAST 资产列表</span>
        </h1>
        <p class="text-xs text-slate-400 mt-1">支持手动添加资产，勾选后按模板与探测端口发起动态扫描</p>
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
    <div class="bg-white rounded-xl border border-slate-200/80 px-5 py-3 shadow-2xs flex flex-wrap items-end gap-3 shrink-0">
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
      <a-button size="small" type="primary" class="ml-auto" @click="showAddAsset = true">
        <template #icon><Plus class="w-3 h-3 inline-block mr-1" /></template>
        添加
      </a-button>
    </div>

    <!-- 资产列表卡片（卡片内独立滚动） -->
    <div class="bg-white rounded-xl border border-slate-200/80 p-5 shadow-2xs flex-1 min-h-0 overflow-hidden flex flex-col">
      <div class="flex-1 overflow-y-auto">
        <a-table
          :columns="columns"
          :data-source="assets"
          :loading="loading"
          :row-selection="rowSelection"
          :row-key="assetKey"
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
              当前筛选范围内没有资产，可点击“添加”手动录入
            </div>
          </template>
        </a-table>
      </div>
    </div>

    <a-modal
      v-model:open="showAddAsset"
      title="添加资产"
      width="640px"
      :confirm-loading="addingAsset"
      ok-text="添加"
      cancel-text="取消"
      @ok="submitAddAsset"
    >
      <a-form layout="vertical" class="mt-4">
        <a-form-item label="IP 地址" required>
          <a-input
            v-model:value="assetIP"
            placeholder="例如 192.168.1.100 或 2001:db8::1"
            allow-clear
            @press-enter="submitAddAsset"
          />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 发起扫描弹窗 -->
    <a-modal
      v-model:open="showCreate"
      title="发起 DAST 动态扫描"
      width="600px"
      :confirm-loading="creating"
      ok-text="创建扫描"
      cancel-text="取消"
      @ok="submitCreate"
    >
      <a-form :model="form" layout="vertical" class="mt-4 space-y-4">
        <div class="text-xs text-slate-500 bg-slate-50 p-2.5 rounded-lg border border-slate-200/60 leading-relaxed">
          💡 <strong>指纹与模板自动适配</strong>：扫描器将先进行目标端口与服务指纹探测，识别开放协议与组件版本后由系统自动匹配适用的 PoC 规则进行验证。
        </div>

        <a-form-item label="探测端口">
          <a-input
            v-model:value="portRangeInput"
            placeholder="默认所有端口 (1-65535)，支持如 80,443,8000-8080 或 1-65535"
            allow-clear
          />
          <div class="text-[11px] text-slate-400 mt-1">
            留空默认扫描全端口 (1-65535)，支持单端口与区间范围 (如 1-1000)，统一采用 TCP 协议探测。
          </div>
        </a-form-item>

        <div class="grid grid-cols-3 gap-3">
          <a-form-item label="速率上限 (Req/s)">
            <a-input-number v-model:value="form.rate_limit" :min="1" :max="5000" class="w-full" placeholder="默认 1000" />
          </a-form-item>
          <a-form-item label="PoC 并发数">
            <a-input-number v-model:value="form.concurrency" :min="1" :max="100" class="w-full" placeholder="默认 10" />
          </a-form-item>
          <a-form-item label="超时时限 (秒)">
            <a-input-number v-model:value="form.timeout_seconds" :min="60" :max="86400" class="w-full" placeholder="默认 600" />
          </a-form-item>
        </div>

        <a-collapse :bordered="false" class="bg-transparent -mx-4">
          <a-collapse-panel key="advanced" header="高级选项（选填）">
            <div class="grid grid-cols-2 gap-4">
              <a-form-item label="模板版本">
                <a-input v-model:value="form.template_version" placeholder="留空由系统自动匹配 Worker 版本" allow-clear />
              </a-form-item>
              <a-form-item label="指定模板 ID">
                <a-select
                  v-model:value="form.template_ids"
                  mode="tags"
                  placeholder="留空自动匹配全部适用规则"
                  allow-clear
                />
              </a-form-item>
            </div>
          </a-collapse-panel>
        </a-collapse>
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
const showAddAsset = ref(false)
const addingAsset = ref(false)
const selectedKeys = ref<string[]>([])

const assetIP = ref('')

const filter = reactive<DastAssetFilter>({
  source_id: '',
  cluster_id: '',
  network_zone: '',
  business_id: '',
})

const portRangeInput = ref('1-65535')

const form = reactive({
  template_version: '',
  template_ids: [] as string[],
  rate_limit: 1000,
  concurrency: 10,
  timeout_seconds: 600,
})

function parsePortRange(raw: string): DastPortSpec[] {
  const text = raw.trim()
  if (!text || text.toLowerCase() === 'all' || text === '所有' || text === '全部') {
    return Array.from({ length: 65535 }, (_, i) => ({ port: i + 1, transport: 'tcp' as const }))
  }
  const set = new Set<number>()
  for (const seg of text.split(/[,，\s]+/)) {
    if (!seg) continue
    const parts = seg.split('-')
    if (parts.length === 1) {
      const p = parseInt(parts[0], 10)
      if (p >= 1 && p <= 65535) set.add(p)
    } else if (parts.length === 2) {
      const start = parseInt(parts[0], 10)
      const end = parseInt(parts[1], 10)
      if (start >= 1 && end <= 65535 && start <= end) {
        for (let p = start; p <= end; p++) {
          set.add(p)
        }
      }
    }
  }
  if (set.size === 0) {
    return Array.from({ length: 65535 }, (_, i) => ({ port: i + 1, transport: 'tcp' as const }))
  }
  return Array.from(set).sort((a, b) => a - b).map((p) => ({ port: p, transport: 'tcp' as const }))
}

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

function assetKey(asset: DastAsset) {
  return JSON.stringify([asset.source_id, asset.cmdb_id])
}

const selected = computed(() => assets.value.filter((a) => selectedKeys.value.includes(assetKey(a))))

async function submitAddAsset() {
  const host = assetIP.value.trim()
  if (!host) {
    message.warning('请输入目标 IP 地址')
    return
  }
  addingAsset.value = true
  try {
    const asset = await api.createDastAsset({ host })
    Object.assign(filter, {
      source_id: asset.source_id,
      cluster_id: asset.cluster_id,
      network_zone: asset.network_zone,
      business_id: asset.business_id,
    })
    selectedKeys.value = []
    showAddAsset.value = false
    assetIP.value = ''
    message.success('资产已添加')
    await load()
  } catch (e: any) {
    message.error(e.message)
  } finally {
    addingAsset.value = false
  }
}

async function load() {
  loading.value = true
  try {
    assets.value = await api.listDastAssets({
      source_id: filter.source_id || undefined,
      cluster_id: filter.cluster_id || undefined,
      network_zone: filter.network_zone || undefined,
      business_id: filter.business_id || undefined,
    })
  } catch (e: any) {
    message.error(e.message)
  } finally {
    loading.value = false
  }
}

async function submitCreate() {
  if (selected.value.length === 0) {
    message.warning('请至少勾选一个目标资产')
    return
  }
  const ports = parsePortRange(portRangeInput.value)
  const reqKey = `scan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  creating.value = true
  try {
    const scan = await api.createDastScan({
      request_key: reqKey,
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
        rate_limit: form.rate_limit || 1000,
        concurrency: form.concurrency || 10,
        timeout_seconds: form.timeout_seconds || 600,
        probe_ports: ports,
      },
    })
    message.success(`批次 #${scan.id} 已创建，任务已进入执行队列`)
    showCreate.value = false
    selectedKeys.value = []
    router.push(`/dast/tasks/${scan.id}`)
  } catch (e: any) {
    message.error(e?.response?.data?.error || e?.message || '创建扫描失败')
  } finally {
    creating.value = false
  }
}

onMounted(load)
</script>
