<template>
  <div class="space-y-3">
    <p class="text-xs text-slate-500">仓库原始 YAML，可直接下载，无需 AI 重写。收录不代表已验证漏洞。</p>
    <details v-for="template in templates" :key="template.source" class="border border-slate-200 rounded p-3">
      <summary class="text-sm cursor-pointer break-all">{{template.source.split('/').pop()}}</summary>
      <div class="flex gap-3 items-center mt-3"><a :href="template.source" target="_blank" rel="noopener noreferrer" class="text-xs">查看来源</a><a-button size="small" @click="download(template)">下载 YAML</a-button></div>
      <pre class="text-xs whitespace-pre-wrap max-h-96 overflow-auto mt-3 bg-slate-50 p-3">{{template.text}}</pre>
    </details>
  </div>
</template>
<script setup lang="ts">
import type {Evidence} from '@/api/poc'
defineProps<{templates:Evidence[]}>()
function download(template:Evidence){const url=URL.createObjectURL(new Blob([template.text],{type:'application/yaml'}));const a=document.createElement('a');a.href=url;a.download=template.source.split('/').pop()!;a.click();URL.revokeObjectURL(url)}
</script>
