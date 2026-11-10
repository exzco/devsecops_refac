<template>
  <div class="text-xs space-y-3 py-2 px-4">
    <!-- 消息描述 -->
    <div>
      <span class="text-gray-400 mr-2">描述：</span>
      <span class="text-gray-700">{{ finding.message || '—' }}</span>
    </div>

    <!-- 主位置代码片段 -->
    <template v-if="primary">
      <div class="font-mono text-xs text-gray-500 mb-1">
        📄 {{ primary.uri }}:{{ primary.startLine }}
      </div>
      <pre v-if="primary.snippet" class="bg-gray-900 text-green-300 rounded p-3 overflow-x-auto text-xs leading-relaxed">{{ primary.snippet }}</pre>
    </template>

    <!-- CWE -->
    <div v-if="finding.cwes?.length">
      <span class="text-gray-400 mr-2">CWE：</span>
      <a-tag v-for="cwe in finding.cwes" :key="cwe" color="orange">{{ cwe }}</a-tag>
    </div>

    <!-- 相关位置 -->
    <div v-if="finding.related_locations?.length">
      <div class="text-gray-400 mb-1">相关位置：</div>
      <div
        v-for="(loc, i) in finding.related_locations"
        :key="i"
        class="font-mono text-gray-600 text-xs"
      >
        {{ loc.uri }}:{{ loc.startLine }}
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { Finding } from '@/types'

const props = defineProps<{ finding: Finding }>()
const primary = computed(() => props.finding.locations?.[0] ?? null)
</script>
