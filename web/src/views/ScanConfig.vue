<template>
  <div class="h-full flex flex-col overflow-hidden gap-4">
    <div class="bg-white rounded-xl border border-slate-200/80 p-5 shadow-2xs shrink-0">
      <h1 class="text-base font-bold text-slate-800 flex items-center gap-2">
        <Settings class="w-4 h-4 text-blue-500" />
        <span>SAST 扫描任务引擎与策略配置</span>
      </h1>
      <p class="text-xs text-slate-400 mt-1">查看系统 CodeQL 静态分析引擎、默认规则套件以及队列配置参数</p>
    </div>

    <!-- 配置详情表格卡片（独立滚动） -->
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 flex-1 min-h-0 overflow-y-auto pr-1">
      <div class="bg-white rounded-xl border border-slate-200/80 p-5 shadow-2xs space-y-4">
        <h2 class="text-sm font-bold text-slate-800 border-b border-slate-100 pb-2">扫描器核心配置 (SASTScanner)</h2>
        <div class="space-y-3 text-xs">
          <div class="flex justify-between py-1 border-b border-slate-50">
            <span class="text-slate-400">CodeQL CLI 路径</span>
            <span class="font-mono font-medium text-slate-700">/home/wsh/sdk/codeql/codeql</span>
          </div>
          <div class="flex justify-between py-1 border-b border-slate-50">
            <span class="text-slate-400">默认规则套件 (Suite)</span>
            <span class="font-mono font-medium text-blue-600">security-extended</span>
          </div>
          <div class="flex justify-between py-1 border-b border-slate-50">
            <span class="text-slate-400">扫描工作区根目录</span>
            <span class="font-mono font-medium text-slate-700">/home/wsh/devsecops-v2/dev-v2/internal/sast/result</span>
          </div>
          <div class="flex justify-between py-1 border-b border-slate-50">
            <span class="text-slate-400">支持的语言</span>
            <span class="font-medium text-slate-700">Go, Java, Kotlin, Python, JavaScript, TypeScript</span>
          </div>
        </div>
      </div>

      <div class="bg-white rounded-xl border border-slate-200/80 p-5 shadow-2xs space-y-4">
        <h2 class="text-sm font-bold text-slate-800 border-b border-slate-100 pb-2">任务调度与心跳参数</h2>
        <div class="space-y-3 text-xs">
          <div class="flex justify-between py-1 border-b border-slate-50">
            <span class="text-slate-400">Redis 任务队列名</span>
            <span class="font-mono font-medium text-slate-700">sast:scan:queue</span>
          </div>
          <div class="flex justify-between py-1 border-b border-slate-50">
            <span class="text-slate-400">Worker 注册注册表</span>
            <span class="font-mono font-medium text-slate-700">sast:workers</span>
          </div>
          <div class="flex justify-between py-1 border-b border-slate-50">
            <span class="text-slate-400">Worker 心跳间隔</span>
            <span class="font-mono font-medium text-emerald-600">10 秒</span>
          </div>
          <div class="flex justify-between py-1 border-b border-slate-50">
            <span class="text-slate-400">Worker 心跳 TTL</span>
            <span class="font-mono font-medium text-slate-700">30 秒</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { Settings } from 'lucide-vue-next'
</script>
