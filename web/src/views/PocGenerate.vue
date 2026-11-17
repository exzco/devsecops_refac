<template>
  <div class="h-full overflow-auto space-y-4">
    <div class="bg-white border border-slate-200 rounded-xl p-5 flex items-center justify-between gap-4">
      <div><h1 class="font-bold text-slate-800">PoC 生成</h1><p class="text-xs text-slate-500 mt-1">分别生成产品指纹和漏洞探测模板</p></div>
      <div class="flex gap-2"><a-button @click="openSettings">API 配置</a-button><a-button @click="router.push('/dast/pocs')">规则列表</a-button></div>
    </div>

    <div class="bg-white border border-slate-200 rounded-xl p-5">
      <label class="block text-sm font-medium text-slate-700 mb-2">CVE 编号</label>
      <div class="flex flex-wrap gap-3">
        <a-input v-model:value="cveID" placeholder="例如 CVE-2024-3094" class="!max-w-md" allow-clear @press-enter="loadContext()" />
        <a-button :loading="state.status==='loading'" :disabled="!validID" @click="loadContext()">读取信息</a-button>
        <a-button :disabled="!validID || state.status==='loading'" @click="loadContext(true)">更新来源</a-button>
        <a-button type="primary" :loading="submitting" :disabled="state.status!=='ready' || state.data.cve.id!==normalizedID || !agent || !!agent.configuration_error" @click="generate">生成 PoC</a-button>
      </div>
      <div class="flex flex-wrap justify-between gap-2 text-xs mt-3">
        <span class="text-slate-400">优先读取已收集的信息，缺失时按编号获取。点击生成后才调用 AI。</span>
        <button class="text-blue-600 cursor-pointer" @click="openSettings">{{agent?.configuration_error ? '配置 AI 服务' : agent ? `${agent.protocol} · ${agent.model}` : 'API 配置'}}</button>
      </div>
      <div v-if="state.status==='error'" class="text-sm text-red-600 mt-4">{{state.message}}</div>
    </div>

    <div v-if="state.status==='ready' && state.data.cve.id===normalizedID" class="bg-white border border-slate-200 rounded-xl overflow-hidden">
      <div class="px-5 py-4 border-b border-slate-100 flex justify-between items-center"><h2 class="font-semibold">{{state.data.cve.id}}</h2><span class="text-xs text-emerald-600">已载入 {{state.data.materials.length}} 份来源信息</span></div>
      <div class="p-5 space-y-5">
        <div v-if="state.data.notices.length" class="text-xs text-amber-700 whitespace-pre-line">{{state.data.notices.join('\n')}}</div>
        <section><h3 class="text-xs text-slate-400 mb-2">漏洞描述</h3><p class="text-sm text-slate-700 whitespace-pre-wrap max-h-52 overflow-auto">{{state.data.description || '已收集的数据中暂无描述'}}</p></section>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
          <section><h3 class="text-xs text-slate-400 mb-2">匹配的产品档案</h3><div v-for="product in state.data.products" :key="product.key" class="text-sm mb-1">{{product.name}}</div><p v-if="!state.data.products.length" class="text-sm text-slate-500">暂无匹配档案，生成时从 CVE 信息识别产品。</p></section>
          <section><h3 class="text-xs text-slate-400 mb-2">信息来源</h3><div class="flex flex-wrap gap-2"><a-tag v-for="name in Object.keys(state.data.cve.sources)" :key="name">{{name}}</a-tag></div></section>
        </div>
        <section v-if="links.length"><h3 class="text-xs text-slate-400 mb-2">相关链接</h3><div class="max-h-40 overflow-auto space-y-2"><a v-for="link in links" :key="link.url" :href="link.url" target="_blank" rel="noopener noreferrer" class="block text-xs break-all">{{link.title || link.url}}</a></div></section>
        <details class="border-t border-slate-100 pt-3"><summary class="text-xs text-slate-500 cursor-pointer">查看自动带入的材料</summary><div v-for="(material,i) in state.data.materials" :key="i" class="mt-3"><div class="text-xs font-medium break-all">{{material.source}}</div><pre class="mt-2 text-xs text-slate-500 whitespace-pre-wrap max-h-52 overflow-auto bg-slate-50 rounded p-3">{{material.text}}</pre></div></details>
      </div>
    </div>

    <PocJobs ref="jobs" @completed="loadResults" />
    <div class="bg-white border border-slate-200 rounded-xl p-5">
      <div class="flex justify-between mb-3"><h2 class="font-semibold">生成结果</h2><a-button size="small" @click="loadResults">刷新</a-button></div>
      <a-table :columns="columns" :data-source="generationRows" row-key="id" :pagination="{pageSize:10}" :scroll="{x:900}">
        <template #bodyCell="{column,record}">
          <template v-if="column.key==='cve'"><span class="whitespace-nowrap">{{record.cve_id}}</span><div class="text-xs text-slate-400 mt-1">{{new Date(record.created_at).toLocaleString()}}</div></template>
          <template v-if="column.key==='product'">{{record.spec.name || '尚未识别'}}<div v-if="record.spec.version===1" class="text-xs text-slate-400 mt-1">历史单模板记录</div></template>
          <template v-if="column.key==='fingerprint' || column.key==='vulnerability'">
            <template v-if="record.outcomes[column.key]">
              <div class="flex items-center gap-2"><a-tag :color="record.outcomes[column.key].status==='draft'?'blue':'orange'">{{record.outcomes[column.key].status==='draft'?'已生成 · 待验证':'信息不足'}}</a-tag><a-button v-if="record.templates[column.key]" size="small" @click="download(record.cve_id,record.outcomes[column.key].kind,record.templates[column.key])">下载 YAML</a-button></div>
              <ul v-if="record.outcomes[column.key].missing_information.length" class="list-disc pl-4 text-xs text-slate-600 mt-2 space-y-1"><li v-for="item in record.outcomes[column.key].missing_information" :key="item">{{item}}</li></ul>
            </template>
            <span v-else class="text-xs text-slate-400">历史记录未生成此项</span>
          </template>
          <template v-if="column.key==='action'"><a-button size="small" @click="viewResult(record.id)">查看</a-button></template>
        </template>
      </a-table>
    </div>

    <a-modal v-model:open="settingsOpen" title="API 配置" ok-text="保存配置" cancel-text="取消" :confirm-loading="savingSettings" @ok="saveSettings">
      <a-form layout="vertical" class="mt-4">
        <a-form-item label="协议" required><a-select v-model:value="settings.protocol" :options="protocols" /></a-form-item>
        <a-form-item label="Base URL" required><a-input v-model:value="settings.base_url" :placeholder="baseExamples[settings.protocol]" /><p class="text-xs text-slate-400 mt-1">填写包含版本路径的地址，例如 {{baseExamples[settings.protocol]}}。</p></a-form-item>
        <a-form-item label="模型" required><a-input v-model:value="settings.model" placeholder="填写服务提供的模型名称" /></a-form-item>
        <a-form-item label="API Key"><a-input-password v-model:value="settings.api_key" autocomplete="new-password" :placeholder="agent?.has_api_key ? '已配置，留空保留现有密钥' : '填写 API Key'" /><p class="text-xs text-slate-400 mt-1">更换协议或地址时需重新填写密钥。</p></a-form-item>
        <p v-if="agent?.configuration_error" class="text-xs text-amber-600">{{agent.configuration_error}}</p>
      </a-form>
    </a-modal>
    <a-modal :open="!!current" title="生成结果" width="1000px" :footer="null" @cancel="currentID=undefined">
      <template v-if="current">
        <section v-for="result in current.outcomes" :key="result.kind" class="border border-slate-200 rounded-lg p-4 mt-4">
          <div class="flex justify-between items-center"><h3 class="font-medium">{{checkTypes[result.kind]}}</h3><a-tag :color="result.status==='draft'?'blue':'orange'">{{result.status==='draft'?'已生成 · 待验证':'信息不足'}}</a-tag></div>
          <p class="text-sm text-slate-600 my-3 whitespace-pre-wrap">{{result.reason}}</p>
          <div v-if="result.missing_information.length" class="text-sm text-amber-700 mb-3"><p class="font-medium mb-1">缺少的信息</p><ul class="list-disc pl-5"><li v-for="item in result.missing_information" :key="item">{{item}}</li></ul></div>
          <template v-if="result.yaml"><pre class="text-xs whitespace-pre-wrap bg-slate-50 p-4 max-h-96 overflow-auto">{{result.yaml}}</pre><a-button class="mt-3" @click="download(current.cve_id,result.kind,result.yaml)">下载 YAML</a-button></template>
        </section>
        <details class="mt-4"><summary class="text-xs cursor-pointer text-slate-500">高级：修改生成规格</summary><a-textarea v-model:value="specText" :rows="14" class="mt-3 font-mono" /><a-button class="mt-3" :loading="savingSpec" @click="saveSpec">保存并重新渲染</a-button></details>
      </template>
    </a-modal>
  </div>
</template>
<script setup lang="ts">
import {computed,onMounted,onUnmounted,reactive,ref,watch} from 'vue'
import {useRoute,useRouter} from 'vue-router'
import {message} from 'ant-design-vue'
import PocJobs from '@/components/PocJobs.vue'
import {poc,type AgentSettings,type GenerationContext,type Generation,type PoCKind} from '@/api/poc'
const router=useRouter(),route=useRoute(),cveID=ref(''),agent=ref<AgentSettings>(),results=ref<Generation[]>([]),currentID=ref<number>()
const generationRows=computed(()=>results.value.map(g=>({...g,outcomes:Object.fromEntries(g.spec.results.map(r=>[r.kind,{...r,yaml:g.templates[r.kind]}]))})))
const current=computed(()=>generationRows.value.find(g=>g.id===currentID.value))
const specText=ref(''),savingSpec=ref(false)
const state=ref<{status:'idle'}|{status:'loading'}|{status:'ready';data:GenerationContext}|{status:'error';message:string}>({status:'idle'})
const jobs=ref<InstanceType<typeof PocJobs>>(),submitting=ref(false),settingsOpen=ref(false),savingSettings=ref(false)
const settings=reactive({protocol:'openai',base_url:'',model:'',api_key:''})
const protocols=[{value:'openai',label:'OpenAI 兼容'},{value:'anthropic',label:'Anthropic Messages'},{value:'gemini',label:'Google Gemini'}]
const baseExamples:Record<string,string>={openai:'https://api.openai.com/v1',anthropic:'https://api.anthropic.com/v1',gemini:'https://generativelanguage.googleapis.com/v1beta'}
const normalizedID=computed(()=>cveID.value.trim().toUpperCase()),validID=computed(()=>/^CVE-\d{4}-\d{4,}$/.test(normalizedID.value))
const links=computed(()=>{if(state.value.status!=='ready')return [];const c=state.value.data.cve;return [...new Map([...(c.manual.pocs??[]),...c.discovered,...(c.sources['CVEProject/cvelistV5']?.references??[])].map(l=>[l.url,l])).values()]})
const checkTypes:Record<PoCKind,string>={fingerprint:'指纹探测',vulnerability:'漏洞探测',legacy:'历史模板（类型未标注）'}
const columns=[{title:'CVE / 生成时间',key:'cve',width:190},{title:'产品',key:'product',width:170},{title:'指纹探测',key:'fingerprint'},{title:'漏洞探测',key:'vulnerability'},{title:'操作',key:'action',width:90}]
let timer:ReturnType<typeof setTimeout>|undefined
let request=0
watch(normalizedID,()=>{clearTimeout(timer);request++;state.value={status:'idle'};if(validID.value)timer=setTimeout(loadContext,400)})
async function loadContext(refresh=false){clearTimeout(timer);if(!validID.value)return;const token=++request;state.value={status:'loading'};try{const data=await (refresh ? poc.refreshContext(normalizedID.value) : poc.context(normalizedID.value));if(token===request)state.value={status:'ready',data}}catch(e:any){if(token===request)state.value={status:'error',message:e.message}}}
async function generate(){if(state.value.status!=='ready')return;submitting.value=true;try{await poc.generate([state.value.data.cve.id]);message.success('生成任务已提交');await jobs.value?.load()}catch(e:any){message.error(e.message)}finally{submitting.value=false}}
function openSettings(){if(!agent.value){message.error('API 配置信息尚未加载');return}Object.assign(settings,{protocol:agent.value.protocol,base_url:agent.value.base_url,model:agent.value.model,api_key:''});settingsOpen.value=true}
async function saveSettings(){savingSettings.value=true;try{agent.value=await poc.saveAgent(settings);settings.api_key='';settingsOpen.value=false;message.success('API 配置已保存并生效')}catch(e:any){message.error(e.message)}finally{savingSettings.value=false}}
watch(settingsOpen,open=>{if(!open)settings.api_key=''})
function viewResult(id:number){currentID.value=id;if(!current.value)throw new Error('生成记录不存在');specText.value=JSON.stringify(current.value.spec,null,2)}
async function saveSpec(){if(!current.value)return;const id=current.value.id;savingSpec.value=true;try{await poc.saveSpec(id,JSON.parse(specText.value));results.value=await poc.generations();message.success('规格已保存')}catch(e:any){message.error(e.message)}finally{savingSpec.value=false}}
async function loadResults(){try{results.value=await poc.generations()}catch(e:any){message.error(e.message)}}
function download(cve:string,kind:PoCKind,content:string){const url=URL.createObjectURL(new Blob([content],{type:'application/yaml'}));const a=document.createElement('a');a.href=url;a.download=cve.toLowerCase()+'-'+(kind==='vulnerability'?'verify':kind)+'.yaml';a.click();URL.revokeObjectURL(url)}
onMounted(async()=>{if(typeof route.query.cve==='string')cveID.value=route.query.cve;try{[agent.value,results.value]=await Promise.all([poc.agent(),poc.generations()])}catch(e:any){message.error(e.message)}})
onUnmounted(()=>{clearTimeout(timer);request++})
</script>
