<template>
  <div class="space-y-5">
    <div class="bg-white rounded-xl border border-slate-200/80 p-8 shadow-2xs text-center max-w-2xl mx-auto my-12">
      <div class="w-14 h-14 rounded-2xl bg-blue-50 text-blue-600 flex items-center justify-center text-2xl mx-auto mb-4 shadow-xs">
        <Crosshair class="w-7 h-7" />
      </div>
      <h1 class="text-lg font-bold text-slate-800">{{ title }}</h1>
      <p class="text-xs text-slate-400 mt-2 max-w-md mx-auto leading-relaxed">
        当前模块已纳入统一安全流水线平台规划。静态扫描 (SAST) 模块已全链路贯通，此功能正在接入对应的扫描探测节点。
      </p>

      <div class="mt-6 flex justify-center gap-3">
        <a-button type="primary" @click="$router.push('/dashboard')">返回平台概览</a-button>
        <a-button @click="$router.push('/sast/scans')">查看 SAST 任务</a-button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { Crosshair } from 'lucide-vue-next'

const route = useRoute()
const title = computed(() => (route.meta?.title as string) || '功能建设中')
</script>
