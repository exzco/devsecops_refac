<template>
  <a-config-provider
    :theme="{
      token: {
        colorPrimary: '#1890ff',
        borderRadius: 8,
        colorBgContainer: '#ffffff',
      },
    }"
  >
    <div class="flex h-screen bg-[#f8fafc] text-slate-800 font-sans overflow-hidden">
      <!-- 左侧边栏 -->
      <aside class="w-60 bg-white border-r border-slate-200/80 flex flex-col shrink-0 select-none z-20">
        <!-- Brand Logo -->
        <div class="h-14 flex items-center gap-3 px-5 border-b border-slate-100">
          <div class="w-7 h-7 rounded-lg bg-slate-900 text-white flex items-center justify-center shadow-xs">
            <ShieldCheck class="w-4 h-4 text-emerald-400" />
          </div>
          <span class="text-base font-bold tracking-tight text-slate-900">DevSecOps</span>
        </div>

        <!-- 导航菜单 -->
        <div class="flex-1 overflow-y-auto py-3 px-2">
          <!-- 概览 / Dashboard -->
          <div
            @click="navTo('/dashboard')"
            class="flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium cursor-pointer transition-colors mb-1.5"
            :class="
              currentRoute.startsWith('/dashboard')
                ? 'bg-slate-100/90 text-slate-900 font-semibold'
                : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
            "
          >
            <LayoutDashboard class="w-4 h-4" />
            <span>概览</span>
          </div>

          <!-- SAST 静态扫描 -->
          <div class="mb-1.5">
            <div
              @click="toggleMenu('sast')"
              class="flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium text-slate-600 hover:bg-slate-50 hover:text-slate-900 cursor-pointer transition-colors"
            >
              <div class="flex items-center gap-2.5">
                <Code2 class="w-4 h-4" />
                <span>SAST 静态扫描</span>
              </div>
              <ChevronDown
                class="w-3 h-3 text-slate-400 transition-transform duration-200"
                :class="{ '-rotate-90': !openMenus.sast }"
              />
            </div>
            <div v-show="openMenus.sast" class="pl-7 pr-1 py-0.5 space-y-0.5 text-xs">
              <div
                @click="navTo('/sast/config')"
                class="px-2.5 py-1.5 rounded-md cursor-pointer transition-colors"
                :class="
                  currentRoute === '/sast/config'
                    ? 'text-blue-600 bg-blue-50/60 font-medium'
                    : 'text-slate-500 hover:text-slate-800 hover:bg-slate-50'
                "
              >
                扫描任务配置
              </div>
              <div
                @click="navTo('/sast/scans')"
                class="px-2.5 py-1.5 rounded-md cursor-pointer transition-colors"
                :class="
                  currentRoute.startsWith('/sast/scans')
                    ? 'text-blue-600 bg-blue-50/60 font-medium'
                    : 'text-slate-500 hover:text-slate-800 hover:bg-slate-50'
                "
              >
                任务列表
              </div>
            </div>
          </div>

          <!-- DAST 动态扫描 -->
          <div class="mb-1.5">
            <div
              @click="toggleMenu('dast')"
              class="flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium text-slate-600 hover:bg-slate-50 hover:text-slate-900 cursor-pointer transition-colors"
            >
              <div class="flex items-center gap-2.5">
                <Crosshair class="w-4 h-4" />
                <span>DAST 动态扫描</span>
              </div>
              <ChevronDown
                class="w-3 h-3 text-slate-400 transition-transform duration-200"
                :class="{ '-rotate-90': !openMenus.dast }"
              />
            </div>
            <div v-show="openMenus.dast" class="pl-7 pr-1 py-0.5 space-y-0.5 text-xs">
              <div
                @click="navTo('/dast/assets')"
                class="px-2.5 py-1.5 rounded-md cursor-pointer transition-colors"
                :class="
                  currentRoute === '/dast/assets'
                    ? 'text-blue-600 bg-blue-50/60 font-medium'
                    : 'text-slate-500 hover:text-slate-800 hover:bg-slate-50'
                "
              >
                资产列表
              </div>
              <div
                @click="navTo('/dast/tasks')"
                class="px-2.5 py-1.5 rounded-md cursor-pointer transition-colors"
                :class="
                  currentRoute.startsWith('/dast/tasks')
                    ? 'text-blue-600 bg-blue-50/60 font-medium'
                    : 'text-slate-500 hover:text-slate-800 hover:bg-slate-50'
                "
              >
                任务列表
              </div>
              <div
                @click="navTo('/dast/pocs')"
                class="px-2.5 py-1.5 rounded-md cursor-pointer transition-colors"
                :class="
                  currentRoute === '/dast/pocs'
                    ? 'text-blue-600 bg-blue-50/60 font-medium'
                    : 'text-slate-500 hover:text-slate-800 hover:bg-slate-50'
                "
              >
                PoC 规则管理
              </div>
              <div @click="navTo('/dast/poc-generate')" class="px-2.5 py-1.5 rounded-md cursor-pointer transition-colors" :class="currentRoute === '/dast/poc-generate' ? 'bg-blue-50 text-blue-600' : 'text-slate-500 hover:bg-slate-50'">PoC 生成</div>
            </div>
          </div>

          <!-- SCA 依赖分析 -->
          <div class="mb-1.5">
            <div
              @click="toggleMenu('sca')"
              class="flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium text-slate-600 hover:bg-slate-50 hover:text-slate-900 cursor-pointer transition-colors"
            >
              <div class="flex items-center gap-2.5">
                <Boxes class="w-4 h-4" />
                <span>SCA 依赖分析</span>
              </div>
              <ChevronDown
                class="w-3 h-3 text-slate-400 transition-transform duration-200"
                :class="{ '-rotate-90': !openMenus.sca }"
              />
            </div>
            <div v-show="openMenus.sca" class="pl-7 pr-1 py-0.5 space-y-0.5 text-xs">
              <div
                @click="navTo('/sca/tasks')"
                class="px-2.5 py-1.5 rounded-md cursor-pointer transition-colors"
                :class="
                  currentRoute === '/sca/tasks'
                    ? 'text-blue-600 bg-blue-50/60 font-medium'
                    : 'text-slate-500 hover:text-slate-800 hover:bg-slate-50'
                "
              >
                任务与漏洞清单
              </div>
            </div>
          </div>
        </div>
      </aside>

      <!-- 右侧主区域 -->
      <div class="flex-1 flex flex-col min-w-0 overflow-hidden">
        <!-- 顶部导航栏 -->
        <header class="h-14 bg-white border-b border-slate-200/80 px-6 flex items-center justify-between shrink-0 z-10 shadow-xs">
          <!-- 面包屑 -->
          <div class="flex items-center gap-2 text-xs text-slate-500 font-medium">
            <template v-for="(crumb, idx) in breadcrumbs" :key="crumb">
              <span :class="idx === breadcrumbs.length - 1 ? 'text-slate-800 font-semibold' : 'text-slate-400'">
                {{ crumb }}
              </span>
              <span v-if="idx < breadcrumbs.length - 1" class="text-slate-300">/</span>
            </template>
          </div>
        </header>

        <!-- 页面主视口（无整体外层滚动条，具体到内部卡片滚动） -->
        <main class="flex-1 overflow-hidden p-4 bg-[#f8fafc] flex flex-col min-h-0">
          <router-view />
        </main>
      </div>
    </div>
  </a-config-provider>
</template>

<script setup lang="ts">
import { computed, reactive, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import {
  ShieldCheck,
  LayoutDashboard,
  Code2,
  Crosshair,
  Boxes,
  ChevronDown,
  Bell,
} from 'lucide-vue-next'

const router = useRouter()
const route = useRoute()

const currentRoute = computed(() => route.path)

const openMenus = reactive({
  sast: true,
  dast: true,
  sca: true,
})

function toggleMenu(key: 'sast' | 'dast' | 'sca') {
  openMenus[key] = !openMenus[key]
}

function navTo(path: string) {
  router.push(path)
}

const breadcrumbs = computed(() => {
  return (route.meta?.breadcrumbs as string[]) || ['平台首页', '概览']
})

// 自动根据当前路由展开对应菜单
watch(
  () => route.path,
  (path) => {
    if (path.startsWith('/sast')) openMenus.sast = true
    if (path.startsWith('/dast')) openMenus.dast = true
    if (path.startsWith('/sca')) openMenus.sca = true
  },
  { immediate: true },
)
</script>
