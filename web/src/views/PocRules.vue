<template>
 <div class="h-full overflow-auto space-y-4">
  <div class="bg-white border border-slate-200 rounded-xl p-5 flex justify-between items-center">
   <div>
    <h1 class="font-bold text-lg">PoC 规则管理</h1>
    <p class="text-xs text-slate-500 mt-1">本地数据库已收录 {{ items.length }} 个 CVE（已持久化落库，支持增量跟进）</p>
   </div>
   <div class="flex gap-2">
    <a-button type="primary" @click="syncModalOpen = true">同步外部数据</a-button>
    <a-button @click="router.push('/dast/poc-generate')">PoC 生成</a-button>
    <a-button @click="edit()">手动补充</a-button>
   </div>
  </div>

  <!-- 列表筛选工具栏 -->
  <div class="bg-white border border-slate-200 rounded-xl p-4 flex gap-3 items-center flex-wrap">
   <a-input v-model:value="query" placeholder="搜索 CVE / 标题 / 描述" class="!w-64" allow-clear @pressEnter="load" />
   <a-button type="primary" :loading="loading" @click="load">查询</a-button>
   <a-button :disabled="!/^CVE-\d{4}-\d{4,}$/i.test(query.trim())" :loading="retrieving" @click="lookup">按编号获取</a-button>
   <span class="text-xs text-slate-500">来源筛选</span>
   <a-select v-model:value="sourceFilter" class="!w-64" placeholder="全部来源" allow-clear :options="[
     {value:'github',label:'GitHub'},
     {value:'nvd',label:'NVD'},
     {value:'github-without-nvd',label:'GitHub 有 / NVD 无'}
   ]" @change="load" />

   <!-- 列表时间范围与年份筛选 -->
   <a-select v-model:value="filterYear" class="!w-36" :options="yearOptions" placeholder="CVE 年份" @change="load" />

   <a-button @click="resetAndLoad">重置</a-button>
   <span class="text-xs text-slate-400 ml-auto">展示最新 {{ items.length }} 项</span>
  </div>

  <PocJobs ref="jobs" @completed="load()" />

  <div class="bg-white border border-slate-200 rounded-xl p-4">
   <a-table :columns="columns" :data-source="filtered" row-key="id" :loading="loading" :pagination="{pageSize:20}">
    <template #bodyCell="{column,record}">
     <template v-if="column.key==='cve'">
      <b>{{record.id}}</b>
      <div class="text-xs text-slate-500 mt-1">{{record.manual.title}}</div>
      <div class="text-xs mt-2 line-clamp-3">{{description(record as any)}}</div>
      <div class="text-xs text-slate-400 mt-1">{{Object.keys(record.sources).join(' / ')}}</div>
      <a v-if="sourceFilter==='github-without-nvd'" :href="'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(record.id)" target="_blank" rel="noopener noreferrer" class="text-xs">到 NVD 核对</a>
     </template>
     <template v-if="column.key==='poc'">
      <a-button v-if="record.sources['projectdiscovery/nuclei-templates']?.links?.length" size="small" class="mb-2" @click="openNuclei(record.id)">Nuclei YAML</a-button>
      <div v-for="link in record.manual.pocs" :key="link.url">
       <a :href="link.url" target="_blank" rel="noopener noreferrer">{{link.title || link.url}}</a>
      </div>
      <div
       v-for="link in (expandedDiscovered[record.id] ? record.discovered : record.discovered.slice(0, 5))"
       :key="link.url"
       class="text-xs mt-1"
      >
       候选 · <a :href="link.url" target="_blank" rel="noopener noreferrer">{{link.title}}</a>
      </div>
      <div v-if="record.discovered.length > 5" class="mt-1">
       <button
        type="button"
        class="text-xs text-blue-600 hover:text-blue-800 cursor-pointer"
        @click="toggleDiscovered(record.id)"
       >
        {{ expandedDiscovered[record.id] ? '收起' : `查看更多 (还有 ${record.discovered.length - 5} 条)...` }}
       </button>
      </div>
      <span v-if="!record.manual.pocs?.length && !record.discovered.length" class="text-slate-400">
       {{record.searched_at ? '未找到候选' : '尚未搜索'}}
      </span>
     </template>
     <template v-if="column.key==='updated_at'">
      <span class="text-xs text-slate-500">{{ record.updated_at ? record.updated_at.slice(0, 10) : '-' }}</span>
     </template>
     <template v-if="column.key==='action'">
      <a-button size="small" @click="edit(record as any)">修改</a-button>
     </template>
    </template>
   </a-table>
  </div>

  <a-modal :open="!!nucleiCVE" :title="nucleiCVE + ' · Nuclei YAML'" :footer="null" width="900px" @cancel="nucleiCVE=''">
   <NucleiTemplates v-if="nucleiTemplates?.length" :templates="nucleiTemplates" />
   <p v-else class="text-sm text-slate-500 my-4">尚未收录 YAML 正文，请更新来源。</p>
   <a-button class="mt-3" :loading="refreshingNuclei" @click="refreshNuclei">更新来源</a-button>
  </a-modal>

  <!-- 同步外部数据弹窗 -->
  <a-modal v-model:open="syncModalOpen" title="同步 CVE 与 PoC 数据" ok-text="开始同步" cancel-text="取消" @ok="startSync">
   <div class="space-y-4 py-2">
    <p class="text-xs text-slate-500">
     同步任务在后台执行，数据将直接持久化保存至数据库（已有数据自动增量更新，不会覆盖人工补充）。
    </p>
    <div>
     <div class="text-xs font-medium text-slate-700 mb-2">快捷时间预设：</div>
     <div class="flex gap-2 flex-wrap">
      <a-button size="small" @click="setSyncPreset('2018-today')">2018至今全量同步</a-button>
      <a-button size="small" @click="setSyncPreset('latest-7d')">跟进最新 (近7天)</a-button>
      <a-button size="small" @click="setSyncPreset('latest-30d')">近30天</a-button>
     </div>
    </div>
    <div class="flex items-center gap-2 text-sm pt-2">
     <span class="text-xs text-slate-600">同步范围:</span>
     <input type="date" v-model="syncStart" class="border p-1.5 rounded text-xs flex-1" />
     <span class="text-xs text-slate-400">至</span>
     <input type="date" v-model="syncEnd" class="border p-1.5 rounded text-xs flex-1" />
    </div>
   </div>
  </a-modal>

  <!-- 手动修改/补充弹窗 -->
  <a-modal v-model:open="editing" title="修改 CVE" ok-text="保存" cancel-text="取消" :confirm-loading="saving" width="720px" @ok="save">
   <a-form layout="vertical" class="mt-4">
    <a-form-item label="CVE 编号"><a-input v-model:value="id" :disabled="existing" /></a-form-item>
    <a-form-item label="标题"><a-input v-model:value="manual.title" /></a-form-item>
    <a-form-item label="描述"><a-textarea v-model:value="manual.description" :rows="4" /></a-form-item>
    <a-form-item label="相关链接"><div v-for="(link,i) in manual.pocs" :key="i" class="flex gap-2 mb-2"><a-input v-model:value="link.title" placeholder="名称" /><a-input v-model:value="link.url" placeholder="https://..." /><a-button danger @click="manual.pocs.splice(i,1)">移除</a-button></div><a-button @click="manual.pocs.push({title:'',url:''})">添加链接</a-button></a-form-item>
    <a-form-item label="补充材料 / 备注"><a-textarea v-model:value="manual.notes" :rows="5" /></a-form-item>
   </a-form>
   <div v-if="existing" class="border-t border-slate-100 pt-4">
    <div class="flex justify-between items-center mb-3"><span class="font-medium text-sm">GitHub 相关仓库</span><a-button size="small" @click="search(id)">搜索 GitHub</a-button></div>
    <div
     v-for="link in (modalShowAllDiscovered ? currentRecord?.discovered : currentRecord?.discovered?.slice(0, 5))"
     :key="link.url"
     class="flex justify-between gap-3 py-2 text-xs"
    >
     <a :href="link.url" target="_blank" rel="noopener noreferrer" class="truncate">{{link.title}}</a>
     <a-button size="small" :disabled="manual.pocs.some(p=>p.url===link.url)" @click="manual.pocs.push({...link})">加入相关链接</a-button>
    </div>
    <div v-if="(currentRecord?.discovered?.length ?? 0) > 5" class="mt-2">
     <button
      type="button"
      class="text-xs text-blue-600 hover:text-blue-800 cursor-pointer"
      @click="modalShowAllDiscovered = !modalShowAllDiscovered"
     >
      {{ modalShowAllDiscovered ? '收起' : `查看更多 (还有 ${(currentRecord?.discovered?.length ?? 0) - 5} 条)...` }}
     </button>
    </div>
    <p v-if="!currentRecord?.discovered.length" class="text-xs text-slate-400">{{currentRecord?.searched_at ? '暂无搜索结果，可重新搜索。' : '尚未搜索。搜索在后台执行，完成后结果会更新到这里。'}}</p>
    <a-button v-if="!manual.pocs.length && !currentRecord?.discovered.length" class="mt-3" @click="router.push({path:'/dast/poc-generate',query:{cve:id}})">前往 PoC 生成</a-button>
   </div>
  </a-modal>
 </div>
</template>
<script setup lang="ts">
import {computed,onMounted,ref} from 'vue'
import {useRouter} from 'vue-router'
import {message} from 'ant-design-vue'
import PocJobs from '@/components/PocJobs.vue'
import NucleiTemplates from '@/components/NucleiTemplates.vue'
import {poc,loadCatalog,description,type CVE,type Manual,type Evidence} from '@/api/poc'

const router=useRouter()
const nucleiCVE=ref(''),nucleiTemplates=ref<Evidence[] | null>(null),refreshingNuclei=ref(false)
async function openNuclei(id:string){try{nucleiTemplates.value=await poc.nuclei(id);nucleiCVE.value=id}catch(e:any){message.error(e.message)}}
async function refreshNuclei(){refreshingNuclei.value=true;try{const context=await poc.refreshContext(nucleiCVE.value);nucleiTemplates.value=context.templates;if(context.notices.length)message.warning(context.notices.join('；'));await load()}catch(e:any){message.error(e.message)}finally{refreshingNuclei.value=false}}
const items=ref<CVE[]>([])
const query=ref('')
const sourceFilter=ref<string>()
const filterYear=ref('all')
const filterStart=ref('')
const filterEnd=ref('')
const loading=ref(false)
const saving=ref(false)
const editing=ref(false)
const existing=ref(false)
const id=ref('')
const manual=ref<Manual>({title:'',description:'',pocs:[],notes:''})
const currentRecord=computed(()=>items.value.find(c=>c.id===id.value))
const retrieving=ref(false)
const jobs=ref<InstanceType<typeof PocJobs>>()
const expandedDiscovered=ref<Record<string, boolean>>({})
const modalShowAllDiscovered=ref(false)
function toggleDiscovered(cveId: string) { expandedDiscovered.value[cveId] = !expandedDiscovered.value[cveId] }

// 同步弹窗状态
const syncModalOpen=ref(false)
const syncEnd=ref(new Date().toISOString().slice(0,10))
const syncStart=ref(new Date(Date.now()-7*86400000).toISOString().slice(0,10))

function setSyncPreset(preset: '2018-today' | 'latest-7d' | 'latest-30d') {
 const today=new Date().toISOString().slice(0,10)
 syncEnd.value=today
 if(preset==='2018-today') syncStart.value='2018-01-01'
 else if(preset==='latest-7d') syncStart.value=new Date(Date.now()-7*86400000).toISOString().slice(0,10)
 else if(preset==='latest-30d') syncStart.value=new Date(Date.now()-30*86400000).toISOString().slice(0,10)
}

const yearOptions=[
 {value:'all',label:'全部年份'},
 {value:'2018-2026',label:'2018-2026年'},
 {value:'2026',label:'2026年'},
 {value:'2025',label:'2025年'},
 {value:'2024',label:'2024年'},
 {value:'2023',label:'2023年'},
 {value:'2022',label:'2022年'},
 {value:'2021',label:'2021年'},
 {value:'2020',label:'2020年'},
 {value:'2019',label:'2019年'},
 {value:'2018',label:'2018年'},
]

const columns=[
 {title:'CVE / 描述',key:'cve',width:'45%'},
 {title:'相关链接',key:'poc'},
 {title:'入库时间',key:'updated_at',width:120},
 {title:'操作',key:'action',width:90}
]

const filtered=computed(()=>items.value)

async function load(_?: any){
 loading.value=true
 try{
  items.value=await loadCatalog({
   q:query.value.trim() || undefined,
   source:sourceFilter.value,
   year:filterYear.value!=='all' ? filterYear.value : undefined,
   start:filterStart.value || undefined,
   end:filterEnd.value || undefined,
   limit:200
  })
 }catch(e:any){
  message.error(e.message)
 }finally{
  loading.value=false
 }
}

function resetAndLoad(){
 query.value=''
 sourceFilter.value=undefined
 filterYear.value='all'
 filterStart.value=''
 filterEnd.value=''
 load()
}
function edit(c?:CVE){existing.value=!!c;id.value=c?.id??'';modalShowAllDiscovered.value=false;manual.value={title:c?.manual.title??'',description:c?.manual.description??'',pocs:c?.manual.pocs?.map(l=>({...l}))??[],notes:c?.manual.notes??''};editing.value=true}
async function save(){saving.value=true;try{await poc.save(id.value.trim().toUpperCase(),manual.value);editing.value=false;await load()}catch(e:any){message.error(e.message)}finally{saving.value=false}}
async function lookup(){retrieving.value=true;try{const result=await poc.context(query.value.trim().toUpperCase());await load();if(result.notices.length)message.warning(result.notices.join('；'));else message.success('CVE 信息已获取')}catch(e:any){message.error(e.message)}finally{retrieving.value=false}}
async function startSync(){
 if(!syncStart.value || !syncEnd.value){message.warning('请选择同步起止日期');return}
 try{
  await poc.sync(syncStart.value,syncEnd.value)
  syncModalOpen.value=false
  message.success('已提交同步任务，数据将保存至数据库')
  await jobs.value?.load()
 }catch(e:any){message.error(e.message)}
}
async function search(id:string){try{await poc.search([id]);message.success('搜索任务已提交，完成后会更新相关仓库');await jobs.value?.load()}catch(e:any){message.error(e.message)}}
onMounted(()=>load())
</script>
