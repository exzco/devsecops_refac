<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between">
      <h1 class="text-xl font-semibold text-gray-800">Worker 状态</h1>
      <a-button :loading="loading" @click="load">刷新</a-button>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
      <a-card
        v-for="w in workers"
        :key="w.worker_id"
        size="small"
        :class="w.online ? 'border-green-300' : 'border-gray-200'"
      >
        <div class="flex items-center gap-3">
          <a-badge :status="w.online ? 'success' : 'default'" />
          <div class="flex-1 min-w-0">
            <div class="font-mono text-sm font-medium truncate text-gray-800">{{ w.worker_id }}</div>
            <div class="text-xs text-gray-400 mt-0.5">
              {{ w.online ? '在线' : '离线' }}
              <template v-if="w.last_seen_at">
                · 最后心跳 {{ dayjs(w.last_seen_at).format('HH:mm:ss') }}
              </template>
            </div>
          </div>
        </div>
      </a-card>

      <a-empty v-if="!loading && workers.length === 0" description="暂无 Worker 注册" class="col-span-full py-12" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import dayjs from 'dayjs'
import { api } from '@/api'
import type { WorkerStatus } from '@/types'

const workers = ref<WorkerStatus[]>([])
const loading = ref(false)

async function load() {
  loading.value = true
  try {
    workers.value = await api.listWorkers()
  } catch (e: any) {
    message.error(e.message)
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>
