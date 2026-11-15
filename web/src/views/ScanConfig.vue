<template>
  <div class="h-full flex flex-col overflow-hidden gap-4">
    <!-- 顶部概览栏（固定） -->
    <div class="bg-white rounded-xl border border-slate-200/80 p-5 shadow-2xs shrink-0 flex items-center justify-between">
      <div>
        <h1 class="text-base font-bold text-slate-800 flex items-center gap-2">
          <Settings class="w-4 h-4 text-blue-500" />
          <span>SAST 扫描任务引擎与策略配置</span>
        </h1>
        <p class="text-xs text-slate-400 mt-1">查看系统 CodeQL 静态分析引擎、配置单项 QL 查询规则或组合为多规则扫描套件</p>
      </div>
      <div class="flex items-center gap-2 text-xs text-slate-500">
        <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-50 border border-slate-200/80">
          <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
          当前运行引擎：<strong class="text-slate-700 font-mono">CodeQL v2.19+</strong>
        </span>
      </div>
    </div>

    <!-- 主配置区域：左右双卡片（卡片内独立滚动，无整体页面滚动条） -->
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-4 flex-1 min-h-0 overflow-hidden">
      <!-- 1. 左侧：扫描器核心配置 (4 列) -->
      <div class="lg:col-span-4 flex flex-col bg-white rounded-xl border border-slate-200/80 shadow-2xs overflow-hidden">
        <div class="px-5 py-3.5 border-b border-slate-100 bg-slate-50/60 shrink-0">
          <h2 class="text-sm font-bold text-slate-800 flex items-center gap-2">
            <Settings class="w-4 h-4 text-blue-500" />
            <span>扫描器核心配置 (SASTScanner)</span>
          </h2>
        </div>

        <div class="flex-1 min-h-0 overflow-y-auto p-5 space-y-4 text-xs">
          <div class="space-y-3">
            <div class="flex flex-col gap-1 py-1.5 border-b border-slate-50">
              <span class="text-slate-400 font-medium">CodeQL CLI 路径</span>
              <span class="font-mono text-slate-700 bg-slate-50 px-2 py-1 rounded border border-slate-200/60 break-all select-all">
                /home/wsh/sdk/codeql/codeql
              </span>
            </div>

            <div class="flex justify-between items-center py-1.5 border-b border-slate-50">
              <span class="text-slate-400 font-medium">当前生效组合配置</span>
              <span class="font-mono font-semibold text-blue-600 bg-blue-50 px-2 py-0.5 rounded border border-blue-200 truncate max-w-[200px]" :title="activeSuite?.name">
                {{ activeSuite?.name || 'security-extended' }}
              </span>
            </div>

            <div class="flex flex-col gap-1 py-1.5 border-b border-slate-50">
              <span class="text-slate-400 font-medium">扫描工作区根目录</span>
              <span class="font-mono text-slate-700 bg-slate-50 px-2 py-1 rounded border border-slate-200/60 break-all select-all">
                /home/wsh/devsecops-v2/dev-v2/internal/sast/result
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- 2. 右侧：QL 规则与策略配置（替代原任务调度卡片，8 列） -->
      <div class="lg:col-span-8 flex flex-col bg-white rounded-xl border border-slate-200/80 shadow-2xs overflow-hidden">
        <!-- 卡片头部：标题 + 头部两个按钮 [组合配置] [单个配置] -->
        <div class="px-5 py-3 border-b border-slate-100 flex items-center justify-between shrink-0 bg-slate-50/60">
          <div class="flex items-center gap-2">
            <Boxes class="w-4 h-4 text-blue-600" />
            <h2 class="text-sm font-bold text-slate-800">QL 查询与规则配置</h2>
          </div>

          <!-- 头部两个切换按钮：组合配置 vs 单个配置 -->
          <div class="inline-flex p-0.5 rounded-lg bg-slate-200/80 text-xs font-medium">
            <button
              @click="activeMode = 'combo'"
              class="px-3 py-1 rounded-md transition-all cursor-pointer flex items-center gap-1.5"
              :class="activeMode === 'combo' ? 'bg-white text-slate-900 shadow-xs font-semibold' : 'text-slate-600 hover:text-slate-900'"
            >
              <Layers class="w-3.5 h-3.5 text-blue-600" />
              <span>组合配置</span>
              <span class="px-1.5 py-0.2 rounded-full text-[10px] bg-blue-100 text-blue-700 font-mono">
                {{ comboSuites.length }}
              </span>
            </button>
            <button
              @click="activeMode = 'single'"
              class="px-3 py-1 rounded-md transition-all cursor-pointer flex items-center gap-1.5"
              :class="activeMode === 'single' ? 'bg-white text-slate-900 shadow-xs font-semibold' : 'text-slate-600 hover:text-slate-900'"
            >
              <FileCode class="w-3.5 h-3.5 text-indigo-600" />
              <span>单个配置</span>
              <span class="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-100 text-slate-600 font-mono">
                {{ singleRules.length }}
              </span>
            </button>
          </div>
        </div>

        <!-- 模式 A：组合配置视图 -->
        <template v-if="activeMode === 'combo'">
          <!-- 工具与说明栏 -->
          <div class="px-5 py-2.5 bg-slate-50/40 border-b border-slate-100 flex items-center justify-between shrink-0 text-xs">
            <div class="text-slate-500">
              多个 QL 查询组合的扫描套件
            </div>
            <a-button size="small" type="primary" @click="activeMode = 'single'">
              <template #icon><Plus class="w-3 h-3 inline-block mr-1" /></template>
              新建组合
            </a-button>
          </div>

          <!-- 组合套件列表（卡片内独立滚动） -->
          <div class="flex-1 min-h-0 overflow-y-auto p-4 space-y-3">
            <div
              v-for="suite in comboSuites"
              :key="suite.id"
              class="border rounded-xl p-4 transition-all"
              :class="suite.isActive ? 'border-blue-400 bg-blue-50/20 shadow-2xs' : 'border-slate-200/90 bg-white hover:border-slate-300'"
            >
              <div class="flex items-start justify-between gap-3">
                <div class="space-y-1 flex-1 min-w-0">
                  <div class="flex items-center gap-2 flex-wrap">
                    <span class="font-bold text-sm text-slate-800">{{ suite.name }}</span>
                    <span
                      v-if="suite.isActive"
                      class="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-100 text-blue-700 flex items-center gap-1"
                    >
                      <Check class="w-3 h-3" />
                      当前生效
                    </span>
                    <span
                      v-if="suite.isCustom"
                      class="px-2 py-0.5 rounded text-[10px] font-medium bg-amber-50 text-amber-700 border border-amber-200"
                    >
                      自定义组合
                    </span>
                  </div>
                </div>

                <!-- 启用 / 切换按钮 -->
                <div class="shrink-0 flex flex-col items-end gap-2">
                  <a-button
                    size="small"
                    :type="suite.isActive ? 'default' : 'primary'"
                    :ghost="!suite.isActive"
                    @click="setActiveSuite(suite.id)"
                  >
                    {{ suite.isActive ? '当前使用中' : '设为生效配置' }}
                  </a-button>
                </div>
              </div>

              <!-- 组合包含的语言与规则指标 -->
              <div class="mt-3 pt-3 border-t border-slate-100 flex items-center justify-between text-xs flex-wrap gap-2">

                <div class="flex items-center gap-3">
                  <span class="text-slate-500 font-medium">
                    组合内含 <strong class="text-blue-600">{{ suite.rules.length }}</strong> 项 QL 规则
                  </span>
                  <button
                    @click="toggleSuiteExpand(suite.id)"
                    class="text-blue-600 hover:text-blue-700 cursor-pointer flex items-center gap-0.5"
                  >
                    <span>{{ expandedSuites[suite.id] ? '收起 ql 明细' : '展开 ql 明细' }}</span>
                  </button>
                </div>
              </div>

              <!-- 展开的 QL 规则明细列表 -->
              <div v-if="expandedSuites[suite.id]" class="mt-3 pt-2 border-t border-dashed border-slate-200 space-y-1.5">
                <div class="text-[11px] text-slate-400 mb-1 font-medium">该组合包含 ql：</div>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-1.5">
                  <div
                    v-for="ruleId in suite.rules"
                    :key="ruleId"
                    class="p-2 rounded bg-white border border-slate-200/80 text-xs flex items-center justify-between gap-2"
                  >
                    <div class="flex items-center gap-1.5 min-w-0">
                      <FileCode class="w-3.5 h-3.5 text-blue-500 shrink-0" />
                      <span class="font-mono font-semibold text-slate-700 truncate" :title="getRuleById(ruleId)?.file">
                        {{ getRuleById(ruleId)?.file || ruleId }}
                      </span>
                    </div>
                    <div class="shrink-0 flex items-center gap-1 text-[10px]">
                      <span class="px-1 rounded bg-slate-100 text-slate-500 font-mono">
                        {{ getRuleById(ruleId)?.cwe }}
                      </span>
                      <span
                        class="px-1 rounded font-bold"
                        :class="levelBadgeStyle(getRuleById(ruleId)?.level || 'error')"
                      >
                        {{ levelText(getRuleById(ruleId)?.level || 'error') }}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </template>

        <!-- 模式 B：单个配置视图 -->
        <template v-else>
          <!-- 顶部过滤与组合操作栏 -->
          <div class="px-5 py-2.5 bg-slate-50/60 border-b border-slate-100 flex items-center justify-between flex-wrap gap-2 shrink-0 text-xs">
            <!-- 语言过滤 -->
            <div class="flex items-center gap-1">
              <span class="text-slate-400 mr-1">语言:</span>
              <button
                v-for="lang in languages"
                :key="lang"
                @click="filterLanguage = lang"
                class="px-2 py-0.5 rounded transition-colors cursor-pointer text-[11px]"
                :class="filterLanguage === lang ? 'bg-slate-900 text-white font-medium' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'"
              >
                {{ lang }}
              </button>
            </div>

            <!-- 组合联动操作按钮 -->
            <div class="flex items-center gap-2">
              <a-button size="small" @click="openCreateSingleModal">
                <template #icon><Plus class="w-3 h-3 inline-block mr-1" /></template>
                新建 QL 规则
              </a-button>
              <div class="h-3 w-px bg-slate-300"></div>
              <button
                @click="selectAllFiltered"
                class="text-slate-500 hover:text-slate-800 cursor-pointer font-medium"
              >
                全选 / 取消
              </button>
              <div class="h-3 w-px bg-slate-300"></div>
              <span class="text-slate-500">
                已勾选 <strong class="text-blue-600">{{ selectedRuleIds.length }}</strong> 项 QL 规则
              </span>
              <a-button
                size="small"
                type="primary"
                :disabled="selectedRuleIds.length === 0"
                @click="openCreateComboModal"
              >
                <template #icon><Layers class="w-3 h-3 inline-block mr-1" /></template>
                组合为新配置
              </a-button>
            </div>
          </div>

          <!-- 单项 QL 规则列表（卡片内独立滚动） -->
          <div class="flex-1 min-h-0 overflow-y-auto p-4 space-y-2">
            <div
              v-for="rule in filteredRules"
              :key="rule.id"
              @click="toggleRuleSelect(rule.id)"
              class="p-3 rounded-xl border transition-all cursor-pointer flex items-start gap-3"
              :class="
                selectedRuleIds.includes(rule.id)
                  ? 'border-blue-400 bg-blue-50/30 shadow-2xs'
                  : 'border-slate-200/90 bg-white hover:border-slate-300'
              "
            >
              <!-- 勾选框 -->
              <div class="pt-0.5 shrink-0 text-blue-600">
                <CheckSquare v-if="selectedRuleIds.includes(rule.id)" class="w-4 h-4" />
                <Square v-else class="w-4 h-4 text-slate-300" />
              </div>

              <!-- 规则主体信息 -->
              <div class="flex-1 min-w-0 space-y-1">
                <div class="flex items-center justify-between gap-2 flex-wrap">
                  <div class="flex items-center gap-2">
                    <span class="font-mono font-bold text-xs text-slate-800">{{ rule.file }}</span>
                    <span class="font-medium text-xs text-slate-600">{{ rule.name }}</span>
                  </div>

                  <!-- 严重度与语言 -->
                  <div class="flex items-center gap-1.5">
                    <span class="px-1.5 py-0.2 rounded font-mono text-[10px] bg-slate-100 text-slate-600">
                      {{ rule.language }}
                    </span>
                    <span class="px-1.5 py-0.2 rounded font-mono text-[10px] bg-amber-50 text-amber-700 border border-amber-200">
                      {{ rule.cwe }}
                    </span>
                    <span
                      class="px-1.5 py-0.2 rounded font-bold text-[10px] uppercase"
                      :class="levelBadgeStyle(rule.level)"
                    >
                      {{ levelText(rule.level) }}
                    </span>
                  </div>
                </div>

                <div class="text-[11px] text-slate-500 line-clamp-1">
                  {{ rule.description }}
                </div>

                <!-- 所属组合配置标签与查看 QL 源码按钮 -->
                <div class="flex items-center justify-between pt-1 gap-2 flex-wrap">
                  <div v-if="rule.suites && rule.suites.length > 0" class="flex items-center gap-1.5 flex-wrap">
                    <span class="text-[10px] text-slate-400">所属组合:</span>
                    <span
                      v-for="s in rule.suites"
                      :key="s"
                      class="px-1.5 py-0.2 rounded text-[10px] bg-slate-100 text-slate-600"
                    >
                      {{ s }}
                    </span>
                  </div>
                  <div v-else class="text-[10px] text-slate-400">独立单项规则</div>

                  <button
                    type="button"
                    @click.stop="viewRuleCode(rule)"
                    class="text-[11px] text-blue-600 hover:text-blue-700 font-medium flex items-center gap-1 cursor-pointer shrink-0"
                  >
                    <Code2 class="w-3.5 h-3.5" />
                    <span>查看 QL 源码</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        </template>
      </div>
    </div>

    <!-- 弹窗 1：新建单项 QL 查询规则（支持输入 QL 源码） -->
    <a-modal
      v-model:open="showCreateSingleModal"
      title="新建单项 QL 查询规则"
      width="740px"
      @ok="confirmCreateSingle"
      ok-text="确定创建"
      cancel-text="取消"
    >
      <div class="space-y-3 py-2 text-xs">
        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="block font-semibold text-slate-700 mb-1">QL 文件名 (.ql)</label>
            <a-input v-model:value="newSingleRule.file" placeholder="例如：CustomSqlInjection.ql" />
          </div>
          <div>
            <label class="block font-semibold text-slate-700 mb-1">规则中文名称</label>
            <a-input v-model:value="newSingleRule.name" placeholder="例如：自定义 SQL 注入模式检测规则" />
          </div>
        </div>

        <div class="grid grid-cols-3 gap-3">
          <div>
            <label class="block font-semibold text-slate-700 mb-1">适配编程语言</label>
            <a-select v-model:value="newSingleRule.language" class="w-full" @change="onLanguageChanged">
              <a-select-option value="Go">Go</a-select-option>
              <a-select-option value="Java">Java</a-select-option>
              <a-select-option value="Python">Python</a-select-option>
              <a-select-option value="JavaScript">JavaScript</a-select-option>
            </a-select>
          </div>
          <div>
            <label class="block font-semibold text-slate-700 mb-1">漏洞严重程度</label>
            <a-select v-model:value="newSingleRule.level" class="w-full">
              <a-select-option value="error">高危 (Error)</a-select-option>
              <a-select-option value="warning">中危 (Warning)</a-select-option>
              <a-select-option value="note">低危 (Note)</a-select-option>
            </a-select>
          </div>
          <div>
            <label class="block font-semibold text-slate-700 mb-1">CWE 漏洞编号</label>
            <a-input v-model:value="newSingleRule.cwe" placeholder="例如：CWE-089" />
          </div>
        </div>

        <div>
          <label class="block font-semibold text-slate-700 mb-1">规则说明描述</label>
          <a-input
            v-model:value="newSingleRule.description"
            placeholder="简述该 QL 规则的匹配模式、数据源（Source）或危险汇聚点（Sink）..."
          />
        </div>

        <!-- QL 代码输入区域 -->
        <div>
          <div class="flex items-center justify-between mb-1">
            <label class="block font-semibold text-slate-700 flex items-center gap-1.5">
              <Code2 class="w-3.5 h-3.5 text-blue-500" />
              <span>CodeQL 查询代码 (.ql 源码)</span>
            </label>
            <button
              type="button"
              @click="resetToTemplate"
              class="text-[11px] text-blue-600 hover:text-blue-700 cursor-pointer font-medium"
            >
              填入标准 QL 模板
            </button>
          </div>
          <div class="rounded-lg overflow-hidden border border-slate-300 focus-within:border-blue-500 shadow-2xs">
            <textarea
              v-model="newSingleRule.code"
              rows="10"
              spellcheck="false"
              class="w-full p-3 font-mono text-xs bg-slate-950 text-emerald-400 leading-relaxed outline-none resize-y selection:bg-blue-600"
              placeholder="/** 在此处输入 CodeQL 查询代码 (.ql) */"
            ></textarea>
          </div>
        </div>
      </div>
    </a-modal>

    <!-- 弹窗 2：查看单项 QL 源码 -->
    <a-modal
      v-model:open="showViewCodeModal"
      :title="`CodeQL 规则源码: ${viewingRule?.file || ''}`"
      width="740px"
      :footer="null"
    >
      <div class="py-2 text-xs space-y-2">
        <div class="flex items-center justify-between text-slate-500 font-mono text-[11px] bg-slate-50 p-2 rounded border border-slate-200/80">
          <span class="font-bold text-slate-800">{{ viewingRule?.name }} ({{ viewingRule?.cwe }})</span>
          <div class="flex items-center gap-2">
            <span class="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-700">{{ viewingRule?.language }}</span>
            <span
              class="px-2 py-0.5 rounded font-bold"
              :class="levelBadgeStyle(viewingRule?.level || 'error')"
            >
              {{ levelText(viewingRule?.level || 'error') }}
            </span>
          </div>
        </div>
        <div class="bg-slate-950 text-emerald-400 p-4 rounded-lg font-mono text-xs overflow-x-auto max-h-[460px] leading-relaxed whitespace-pre select-text border border-slate-800 shadow-inner">
          {{ viewingRule?.code || '// 暂无内联 QL 代码' }}
        </div>
      </div>
    </a-modal>

    <!-- 弹窗 2：将勾选的单个 QL 规则保存为组合配置 -->
    <a-modal
      v-model:open="showCreateModal"
      title="将勾选的 QL 规则保存为组合配置"
      @ok="confirmCreateCombo"
      ok-text="确定创建并激活"
      cancel-text="取消"
    >
      <div class="space-y-3 py-2 text-xs">
        <div>
          <label class="block font-semibold text-slate-700 mb-1">组合配置名称</label>
          <a-input v-model:value="newSuiteName" placeholder="xxxx" />
        </div>
        <div>
          <label class="block font-semibold text-slate-700 mb-1">组合说明描述</label>
          <a-textarea v-model:value="newSuiteDesc" :rows="2" placeholder="简述该扫描组合的大致范围" />
        </div>
        <div class="bg-slate-50 p-2.5 rounded border border-slate-200/80">
          <div class="text-slate-500 mb-1 font-medium">
            本次组合的 ql 规则共 {{ selectedRuleIds.length }} 项：
          </div>
          <div class="flex flex-wrap gap-1 max-h-32 overflow-y-auto">
            <span
              v-for="rId in selectedRuleIds"
              :key="rId"
              class="px-2 py-0.5 rounded bg-white border border-slate-200 font-mono text-[11px] text-slate-700"
            >
              {{ getRuleById(rId)?.file || rId }}
            </span>
          </div>
        </div>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { message } from 'ant-design-vue'
import {
  Settings,
  Layers,
  FileCode,
  Check,
  Plus,
  Boxes,
  CheckSquare,
  Square,
  Code2,
} from 'lucide-vue-next'

type ConfigMode = 'combo' | 'single'
const activeMode = ref<ConfigMode>('combo')

interface QLRule {
  id: string
  file: string
  name: string
  language: string
  cwe: string
  level: 'error' | 'warning' | 'note'
  description: string
  suites: string[]
  code?: string
}

interface ComboSuite {
  id: string
  name: string
  suiteFile: string
  description: string
  languages: string[]
  rules: string[]
  isActive: boolean
  isCustom?: boolean
}

// 1. 单个 QL 规则配置清单
const singleRules = ref<QLRule[]>([
  {
    id: 'ql-go-sql',
    file: 'SqlInjection.ql',
    name: 'SQL 注入漏洞检测 (Database Query Taint)',
    language: 'Go',
    cwe: 'CWE-089',
    level: 'error',
    description: '追踪 HTTP 请求参数未经安全净化直接流入 Database SQL 查询语句的危险传播流',
    suites: ['Security-Extended', 'OWASP Top 10', '污点流深度追踪'],
    code: `/**
 * @name SQL injection vulnerability
 * @description Untrusted input concatenated directly into database query
 * @kind problem
 * @problem.severity error
 * @id go/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import go

from CallExpr call, Expr query
where
  call.getTarget().hasQualifiedName("database/sql", "Query") and
  query = call.getArgument(0)
select query, "SQL query contains unescaped input from untrusted source"`,
  },
  {
    id: 'ql-go-cmd',
    file: 'CommandInjection.ql',
    name: '系统命令执行注入 (Command Execution)',
    language: 'Go',
    cwe: 'CWE-078',
    level: 'error',
    description: '检测外部入参未经转义直接传递给 os/exec.Command 系统调用的严重漏洞',
    suites: ['Security-Extended', 'OWASP Top 10'],
    code: `/**
 * @name Command injection
 * @description Executing os commands with unvalidated user input
 * @kind problem
 * @problem.severity error
 * @id go/command-injection
 * @tags security
 *       external/cwe/cwe-078
 */

import go

from CallExpr call, Expr commandArg
where
  call.getTarget().hasQualifiedName("os/exec", "Command") and
  commandArg = call.getArgument(0)
select call, "Dangerous command execution with potentially untrusted arguments"`,
  },
  {
    id: 'ql-go-path',
    file: 'PathTraversal.ql',
    name: '路径穿越与未受限文件读取 (Path Traversal)',
    language: 'Go',
    cwe: 'CWE-022',
    level: 'error',
    description: '检测使用 filepath.Join 或直接读取文件路径时未对 ../ 目录穿越进行过滤',
    suites: ['Security-Extended', '污点流深度追踪'],
    code: `/**
 * @name Path traversal
 * @description Accessing files with unvalidated paths
 * @kind problem
 * @problem.severity error
 * @id go/path-traversal
 * @tags security
 *       external/cwe/cwe-022
 */

import go

from CallExpr call
where call.getTarget().hasQualifiedName("os", "Open")
select call, "File opened without verifying path traversal sanitization"`,
  },
  {
    id: 'ql-go-ssrf',
    file: 'SsrfQuery.ql',
    name: '服务端请求伪造 (SSRF Taint Flow)',
    language: 'Go',
    cwe: 'CWE-918',
    level: 'warning',
    description: '检测由外部可控入参构造目标 URL 并发起 HTTP 客户端请求的操作',
    suites: ['Security-Extended', 'OWASP Top 10'],
    code: `/**
 * @name Server-Side Request Forgery
 * @description Outgoing HTTP request constructed from untrusted URL
 * @kind problem
 * @problem.severity warning
 * @id go/ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

import go

from CallExpr call, Expr urlArg
where
  call.getTarget().hasQualifiedName("net/http", "Get") and
  urlArg = call.getArgument(0)
select call, "Potential SSRF vulnerability from user-controlled URL"`,
  },
  {
    id: 'ql-java-xss',
    file: 'ReflectedXss.ql',
    name: '反射型跨站脚本 (Reflected XSS)',
    language: 'Java',
    cwe: 'CWE-079',
    level: 'warning',
    description: '检测 Web 入参未经过 HTML 转义直接响应在 Servlet / Spring MVC 视图输出流中',
    suites: ['Security-Extended', 'OWASP Top 10'],
    code: `/**
 * @name Reflected cross-site scripting
 * @description Writing untrusted user input directly to HTTP response
 * @kind problem
 * @problem.severity warning
 * @id java/xss
 * @tags security
 *       external/cwe/cwe-079
 */

import java

from MethodAccess call
where
  call.getMethod().hasName("print") and
  call.getQualifier().getType().getName() = "PrintWriter"
select call, "Cross-site scripting vulnerability via unescaped response write"`,
  },
  {
    id: 'ql-java-deser',
    file: 'InsecureDeserialization.ql',
    name: '不安全反序列化 RCE (ObjectInputStream)',
    language: 'Java',
    cwe: 'CWE-502',
    level: 'error',
    description: '检测对不可信输入流直接调用 readObject 反序列化触发的 Gadget 执行链',
    suites: ['Security-Extended'],
    code: `/**
 * @name Deserialization of untrusted data
 * @description ObjectInputStream deserialization with arbitrary classes
 * @kind problem
 * @problem.severity error
 * @id java/insecure-deserialization
 * @tags security
 *       external/cwe/cwe-502
 */

import java

from MethodAccess call
where
  call.getMethod().hasName("readObject") and
  call.getQualifier().getType().getName() = "ObjectInputStream"
select call, "Unsafe deserialization of untrusted input stream"`,
  },
  {
    id: 'ql-py-secret',
    file: 'HardcodedCredentials.ql',
    name: '硬编码高危凭证与密钥泄露 (Hardcoded Secret)',
    language: 'Python',
    cwe: 'CWE-798',
    level: 'warning',
    description: '检测源代码中硬编码的数据库密码、Private Key、API Token 等机密凭据',
    suites: ['Security-Extended', 'OWASP Top 10'],
    code: `/**
 * @name Hardcoded credentials
 * @description Hardcoded password or cryptographic secret key
 * @kind problem
 * @problem.severity warning
 * @id py/hardcoded-credentials
 * @tags security
 *       external/cwe/cwe-798
 */

import python

from StrConst s, Assign stmt
where
  s.getText().regexpMatch("(?i).*(password|secret|apikey).*") and
  stmt.getValue() = s
select stmt, "Hardcoded secret key or password identified in source code"`,
  },
  {
    id: 'ql-js-proto',
    file: 'PrototypePollution.ql',
    name: '原型链污染漏洞 (Prototype Pollution)',
    language: 'JavaScript',
    cwe: 'CWE-1321',
    level: 'warning',
    description: '检测对象递归合并或深拷贝时未限制 __proto__ 或 constructor 属性',
    suites: ['Security-Extended'],
    code: `/**
 * @name Prototype pollution
 * @description Recursive object merge allowing __proto__ modification
 * @kind problem
 * @problem.severity warning
 * @id js/prototype-pollution
 * @tags security
 *       external/cwe/cwe-1321
 */

import javascript

from PropAccess p
where p.getPropertyName() in ["__proto__", "prototype", "constructor"]
select p, "Potential prototype pollution via unsafe property write"`,
  },
])

// 2. 组合配置清单（由单个 QL 互相组合而成）
const comboSuites = ref<ComboSuite[]>([
  {
    id: 'suite-security-extended',
    name: 'Security Extended Suite (高危安全扩展套件)',
    suiteFile: 'codeql-suites/security-extended.qls',
    description: '平台默认启用的全量安全分析套件，全面覆盖 CWE 高危缺陷与全链路跨函数污点流追踪。',
    languages: ['Go', 'Java', 'Python', 'JavaScript'],
    rules: [
      'ql-go-sql',
      'ql-go-cmd',
      'ql-go-path',
      'ql-go-ssrf',
      'ql-java-xss',
      'ql-java-deser',
      'ql-py-secret',
      'ql-js-proto',
    ],
    isActive: true,
  },
  {
    id: 'suite-owasp-top10',
    name: 'OWASP Top 10 Web 风险组合套件',
    suiteFile: 'codeql-suites/owasp-top10.qls',
    description: '紧密对标 OWASP Top 10 评估框架的组合套件，聚焦注入、访问控制失效与敏感信息泄露。',
    languages: ['Go', 'Java', 'Python'],
    rules: ['ql-go-sql', 'ql-go-cmd', 'ql-go-ssrf', 'ql-java-xss', 'ql-py-secret'],
    isActive: false,
  },
  {
    id: 'suite-taint-deep',
    name: 'Taint Flow Deep Propagation (污点流深度追踪套件)',
    suiteFile: 'codeql-suites/taint-deep.qls',
    description: '专攻跨模块、跨函数过程间（Inter-procedural）数据流分析，追踪 Source 入口经清洗到 Sink 汇聚点。',
    languages: ['Go', 'Java'],
    rules: ['ql-go-sql', 'ql-go-path', 'ql-java-xss'],
    isActive: false,
  },
])

// 选中的单个 QL 规则 ID（用于自由组合）
const selectedRuleIds = ref<string[]>(['ql-go-sql', 'ql-go-cmd', 'ql-go-path', 'ql-go-ssrf'])

// 语言过滤
const filterLanguage = ref('全部')
const languages = ['全部', 'Go', 'Java', 'Python', 'JavaScript']

const filteredRules = computed(() => {
  if (filterLanguage.value === '全部') return singleRules.value
  return singleRules.value.filter((r) => r.language === filterLanguage.value)
})

const activeSuite = computed(() => {
  return comboSuites.value.find((s) => s.isActive) || comboSuites.value[0]
})

function getRuleById(id: string): QLRule | undefined {
  return singleRules.value.find((r) => r.id === id)
}

function toggleRuleSelect(id: string) {
  const idx = selectedRuleIds.value.indexOf(id)
  if (idx >= 0) {
    selectedRuleIds.value.splice(idx, 1)
  } else {
    selectedRuleIds.value.push(id)
  }
}

function selectAllFiltered() {
  const currentIds = filteredRules.value.map((r) => r.id)
  const allSelected = currentIds.every((id) => selectedRuleIds.value.includes(id))
  if (allSelected) {
    selectedRuleIds.value = selectedRuleIds.value.filter((id) => !currentIds.includes(id))
  } else {
    selectedRuleIds.value = Array.from(new Set([...selectedRuleIds.value, ...currentIds]))
  }
}

// 展开/折叠明细
const expandedSuites = ref<Record<string, boolean>>({
  'suite-security-extended': true,
})

function toggleSuiteExpand(id: string) {
  expandedSuites.value[id] = !expandedSuites.value[id]
}

function setActiveSuite(targetId: string) {
  comboSuites.value.forEach((s) => {
    s.isActive = s.id === targetId
  })
  message.success('已切换当前生效的 QL 组合配置')
}

// 查看单项 QL 源码弹窗逻辑
const showViewCodeModal = ref(false)
const viewingRule = ref<QLRule | null>(null)

function viewRuleCode(rule: QLRule) {
  viewingRule.value = rule
  showViewCodeModal.value = true
}

// 标准 CodeQL 代码模板生成器
function getQLTemplate(lang: string, cwe: string, level: string, ruleName?: string) {
  const l = lang.toLowerCase() === 'javascript' ? 'javascript' : lang.toLowerCase()
  const cweLower = (cwe || 'cwe-089').toLowerCase()
  const sev = level === 'error' ? 'error' : level === 'warning' ? 'warning' : 'recommendation'
  return `/**
 * @name ${ruleName || 'Custom ' + lang + ' Security Query'}
 * @description 检测代码中的 ${cwe || '安全缺陷与未过滤输入风险'}
 * @kind problem
 * @problem.severity ${sev}
 * @id ${l}/custom-${Date.now().toString().slice(-4)}
 * @tags security
 *       external/cwe/${cweLower}
 */

import ${l}

from Expr source, Expr sink
where
  // 在此处编写 CodeQL 模式匹配谓词与污点追踪规则
  source != sink
select sink, "发现潜在安全缺陷: 汇聚点存在可控输入风险"
`
}

// 新建单项 QL 规则弹窗逻辑
const showCreateSingleModal = ref(false)
const newSingleRule = ref({
  file: '',
  name: '',
  language: 'Go',
  level: 'error' as 'error' | 'warning' | 'note',
  cwe: 'CWE-089',
  description: '',
  code: '',
})

function onLanguageChanged() {
  if (!newSingleRule.value.code || newSingleRule.value.code.startsWith('/**\n * @name Custom')) {
    newSingleRule.value.code = getQLTemplate(
      newSingleRule.value.language,
      newSingleRule.value.cwe,
      newSingleRule.value.level,
      newSingleRule.value.name,
    )
  }
}

function resetToTemplate() {
  newSingleRule.value.code = getQLTemplate(
    newSingleRule.value.language,
    newSingleRule.value.cwe,
    newSingleRule.value.level,
    newSingleRule.value.name,
  )
}

function openCreateSingleModal() {
  const lang = filterLanguage.value !== '全部' ? filterLanguage.value : 'Go'
  newSingleRule.value = {
    file: '',
    name: '',
    language: lang,
    level: 'error',
    cwe: 'CWE-089',
    description: '',
    code: getQLTemplate(lang, 'CWE-089', 'error'),
  }
  showCreateSingleModal.value = true
}

function confirmCreateSingle() {
  if (!newSingleRule.value.file.trim()) {
    message.error('请输入 QL 文件名')
    return
  }
  let fileName = newSingleRule.value.file.trim()
  if (!fileName.endsWith('.ql')) {
    fileName += '.ql'
  }
  if (!newSingleRule.value.name.trim()) {
    message.error('请输入规则中文名称')
    return
  }

  const ruleId = `ql-custom-${Date.now()}`
  const created: QLRule = {
    id: ruleId,
    file: fileName,
    name: newSingleRule.value.name.trim(),
    language: newSingleRule.value.language,
    cwe: newSingleRule.value.cwe.trim() || 'CWE-Custom',
    level: newSingleRule.value.level,
    description: newSingleRule.value.description.trim() || '自定义 CodeQL 静态分析规则',
    suites: [],
    code:
      newSingleRule.value.code.trim() ||
      getQLTemplate(newSingleRule.value.language, newSingleRule.value.cwe, newSingleRule.value.level),
  }

  singleRules.value.unshift(created)
  if (!selectedRuleIds.value.includes(ruleId)) {
    selectedRuleIds.value.push(ruleId)
  }
  showCreateSingleModal.value = false
  message.success(`单项 QL 规则「${fileName}」创建成功，已自动加入待选组合！`)
}

// 组合弹窗逻辑
const showCreateModal = ref(false)
const newSuiteName = ref('')
const newSuiteDesc = ref('')

function openCreateComboModal() {
  if (selectedRuleIds.value.length === 0) {
    message.warning('请先至少勾选 1 项单个 QL 规则！')
    return
  }
  newSuiteName.value = `自定义组合配置 (${selectedRuleIds.value.length} 个 QL 规则)`
  newSuiteDesc.value = '由单个 QL 规则自主挑选与组合而成的定制化扫描套件'
  showCreateModal.value = true
}

function confirmCreateCombo() {
  if (!newSuiteName.value.trim()) {
    message.error('请输入组合配置名称')
    return
  }
  const id = `custom-suite-${Date.now()}`
  const selectedRules = singleRules.value.filter((r) => selectedRuleIds.value.includes(r.id))
  const langs = Array.from(new Set(selectedRules.map((r) => r.language)))

  // 更新各单项规则中的所属组合标签
  const suiteTitle = newSuiteName.value.trim()
  selectedRules.forEach((r) => {
    if (!r.suites.includes(suiteTitle)) {
      r.suites.push(suiteTitle)
    }
  })

  comboSuites.value.unshift({
    id,
    name: suiteTitle,
    suiteFile: `codeql-suites/custom-${Date.now().toString().slice(-4)}.qls`,
    description: newSuiteDesc.value.trim() || '用户自定义组合套件',
    languages: langs,
    rules: [...selectedRuleIds.value],
    isActive: true,
    isCustom: true,
  })

  // 设为当前激活
  comboSuites.value.forEach((s) => {
    if (s.id !== id) s.isActive = false
  })
  expandedSuites.value[id] = true
  showCreateModal.value = false
  activeMode.value = 'combo'
  message.success(`成功创建并激活组合配置「${suiteTitle}」！`)
}

function levelText(level: string) {
  return { error: '高危', warning: '中危', note: '低危' }[level] ?? level
}

function levelBadgeStyle(level: string) {
  return (
    {
      error: 'bg-rose-50 text-rose-600 border border-rose-200',
      warning: 'bg-amber-50 text-amber-700 border border-amber-200',
      note: 'bg-blue-50 text-blue-600 border border-blue-200',
    }[level] ?? 'bg-slate-100 text-slate-600'
  )
}
</script>
