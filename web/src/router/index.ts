import { createRouter, createWebHistory } from 'vue-router'

export default createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: '/dashboard' },
    {
      path: '/dashboard',
      component: () => import('@/views/Dashboard.vue'),
      meta: { title: '概览', breadcrumbs: ['平台首页', '概览'] },
    },
    // SAST
    {
      path: '/sast/config',
      component: () => import('@/views/ScanConfig.vue'),
      meta: { title: '扫描任务配置', breadcrumbs: ['平台首页', 'SAST 静态扫描', '扫描任务配置'] },
    },
    {
      path: '/sast/scans',
      component: () => import('@/views/ScanList.vue'),
      meta: { title: '任务列表', breadcrumbs: ['平台首页', 'SAST 静态扫描', '任务列表'] },
    },
    {
      path: '/sast/scans/:id',
      component: () => import('@/views/ScanDetail.vue'),
      meta: { title: '扫描详情', breadcrumbs: ['平台首页', 'SAST 静态扫描', '扫描详情'] },
    },
    // DAST
    {
      path: '/dast/assets',
      component: () => import('@/views/DastAssets.vue'),
      meta: { title: '资产列表', breadcrumbs: ['平台首页', 'DAST 动态扫描', '资产列表'] },
    },
    {
      path: '/dast/tasks',
      component: () => import('@/views/DastTaskList.vue'),
      meta: { title: 'DAST 任务列表', breadcrumbs: ['平台首页', 'DAST 动态扫描', '任务列表'] },
    },
    {
      path: '/dast/tasks/:id',
      component: () => import('@/views/DastTaskDetail.vue'),
      meta: { title: '扫描详情', breadcrumbs: ['平台首页', 'DAST 动态扫描', '任务列表', '扫描详情'] },
    },
    {
      path: '/dast/pocs',
      component: () => import('@/views/PlaceholderView.vue'),
      meta: { title: 'PoC 规则管理', breadcrumbs: ['平台首页', 'DAST 动态扫描', 'PoC 规则管理'] },
    },
    // SCA
    {
      path: '/sca/tasks',
      component: () => import('@/views/PlaceholderView.vue'),
      meta: { title: 'SCA 任务与漏洞清单', breadcrumbs: ['平台首页', 'SCA 依赖分析', '任务与漏洞清单'] },
    },
    // Compat redirects
    { path: '/sast/repos', redirect: '/sast/scans' },
    { path: '/scans', redirect: '/sast/scans' },
    { path: '/scans/:id', redirect: (to) => `/sast/scans/${to.params.id}` },
    { path: '/workers', redirect: '/dashboard' },
  ],
})
