<template>
  <div class="h-full overflow-y-auto space-y-4">
    <div class="bg-white rounded-xl border border-slate-200 p-5 flex items-center justify-between">
      <div>
        <h1 class="text-base font-bold text-slate-800">SAST 扫描规则</h1>
        <p class="text-xs text-slate-500 mt-1">Worker 开始任务时读取已保存的套件。正在执行的任务沿用原配置。</p>
      </div>
      <div class="flex gap-2">
        <a-button :disabled="busy" @click="load">重新加载</a-button>
        <a-button type="primary" :disabled="!policy" :loading="busy" @click="save">保存配置</a-button>
      </div>
    </div>
    <fieldset v-if="policy" :disabled="busy" class="space-y-4">
      <div class="bg-white rounded-xl border border-slate-200 p-5">
        <label class="text-sm font-semibold">生效套件
          <select v-model="policy.active" class="ml-3 rounded border p-2">
            <option value="code-scanning">code-scanning</option>
            <option value="security-extended">security-extended</option>
            <option v-for="s in policy.suites" :key="s.id" :value="s.id">{{ s.name }}</option>
          </select>
        </label>
      </div>
      <div class="bg-white rounded-xl border border-slate-200 p-5 space-y-3">
        <div class="flex items-center justify-between"><h2 class="font-semibold">自定义套件</h2><a-button @click="addSuite">添加套件</a-button></div>
        <p v-if="!policy.suites.length" class="text-sm text-slate-500">还没有自定义套件。添加单项规则后，可在这里组合。</p>
        <div v-for="suite in policy.suites" :key="suite.id" class="border-t pt-3 space-y-2">
          <div class="flex gap-3"><a-input v-model:value="suite.name" placeholder="套件名称" /><a-button danger :disabled="policy.active === suite.id" @click="removeSuite(suite.id)">删除</a-button></div>
          <div class="flex flex-wrap gap-3 text-sm">
            <label v-for="rule in policy.rules" :key="rule.id"><input v-model="suite.rules" type="checkbox" :value="rule.id" /> {{ rule.name }} · {{ rule.language }}</label>
          </div>
        </div>
      </div>
      <div class="bg-white rounded-xl border border-slate-200 p-5 space-y-3">
        <div class="flex items-center justify-between"><h2 class="font-semibold">单项 QL 规则</h2><a-button @click="addRule">添加规则</a-button></div>
        <details v-for="rule in policy.rules" :key="rule.id" class="border-t pt-3">
          <summary class="cursor-pointer">{{ rule.name || '新规则' }} · {{ rule.language }}</summary>
          <div class="flex gap-3 my-3">
            <a-input v-model:value="rule.name" placeholder="规则名称" />
            <select v-model="rule.language" class="rounded border px-2"><option v-for="lang in languages" :key="lang">{{ lang }}</option></select>
            <a-button danger @click="removeRule(rule.id)">删除</a-button>
          </div>
          <a-textarea v-model:value="rule.code" :rows="10" class="font-mono" placeholder="输入完整的 CodeQL 查询" />
        </details>
      </div>
    </fieldset>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { message } from 'ant-design-vue'
import { http } from '@/api'

interface Policy {
  active: string
  rules: { id: string; name: string; language: string; code: string }[]
  suites: { id: string; name: string; rules: string[] }[]
}
const languages = ['go', 'java', 'javascript', 'python']
const policy = ref<Policy>()
const revision = ref(0)
const busy = ref(false)

async function load() {
  busy.value = true
  try {
    const { data } = await http.get<{ policy: Policy; revision: number }>('/sast/policy')
    policy.value = data.policy
    revision.value = data.revision
  } catch (e: any) { message.error(e.message) }
  finally { busy.value = false }
}

async function save() {
  busy.value = true
  try {
    const { data } = await http.put<{ revision: number }>('/sast/policy', { policy: policy.value, revision: revision.value })
    revision.value = data.revision
    message.success('配置已保存')
  } catch (e: any) { message.error(e.message) }
  finally { busy.value = false }
}

function addRule() {
  policy.value?.rules.push({ id: `rule-${Date.now()}`, name: '', language: 'go', code: '' })
}

function addSuite() {
  policy.value?.suites.push({ id: `suite-${Date.now()}`, name: '', rules: [] })
}

function removeSuite(id: string) {
  if (policy.value) policy.value.suites = policy.value.suites.filter(s => s.id !== id)
}

function removeRule(id: string) {
  if (!policy.value) return
  const suite = policy.value.suites.find(s => s.rules.includes(id))
  if (suite) { message.warning(`请先在套件「${suite.name}」中取消勾选此规则`); return }
  policy.value.rules = policy.value.rules.filter(r => r.id !== id)
}

onMounted(load)
</script>
