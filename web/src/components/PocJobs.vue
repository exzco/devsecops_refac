<template>
  <div class="bg-white border border-slate-200 rounded-xl p-4 text-xs">
    <div class="flex justify-between mb-2"><span class="font-semibold">后台任务</span><a-button size="small" @click="load">刷新</a-button></div>
    <div v-for="job in jobs.slice(0, 5)" :key="job.id" class="py-2 border-t border-slate-100">
      #{{ job.id }} · {{ job.kind }} · {{ labels[job.status] }} <span class="ml-2 text-slate-500">{{ job.progress }}</span>
      <div v-if="job.error" class="text-red-600 mt-1">{{ job.error }}</div>
    </div>
    <span v-if="!jobs.length" class="text-slate-400">暂无任务</span>
  </div>
</template>
<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { message } from 'ant-design-vue'
import { poc, type Job } from '@/api/poc'
const emit = defineEmits<{ completed: [] }>()
const jobs = ref<Job[]>([])
const labels: Record<string,string> = { queued: '排队', running: '执行中', done: '完成', partial: '部分完成', failed: '失败' }
let timer: ReturnType<typeof setTimeout> | undefined
async function load() {
  clearTimeout(timer)
  try {
    const next = await poc.jobs()
    if (jobs.value.some(j => ['queued','running'].includes(j.status) && next.some(n => n.id === j.id && ['done','partial','failed'].includes(n.status)))) emit('completed')
    jobs.value = next
    if (next.some(j => ['queued','running'].includes(j.status))) timer = setTimeout(load, 4000)
  } catch (e: any) { message.error(e.message) }
}
onMounted(load)
onUnmounted(() => clearTimeout(timer))
defineExpose({ load })
</script>
