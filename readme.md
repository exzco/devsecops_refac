# DevSecOps

白盒（SAST）与动态（DAST）漏洞扫描平台：一个 HTTP 服务提供 API 与内置前端，两个 worker 分别执行代码扫描与资产扫描，结果统一落在 PostgreSQL。

## 组成

| 组件 | 入口 | 职责 |
| --- | --- | --- |
| server | `cmd/server/main.go` | HTTP API 与内嵌前端；批次、任务、结果的查询与编排 |
| worker-sast | `cmd/worker-sast/main.go` | 消费 SAST 队列，用 CodeQL 扫描源码仓库 |
| worker-dast | `cmd/worker-dast/main.go` | 消费 DAST 队列，用 nmap + nuclei 扫描资产 |
| web | `web/` | Vue 3 前端，构建产物由 `internal/webui` 内嵌进 server |

两个 worker 都直接连接 PostgreSQL 与 Redis：server 只负责 API 与编排，扫描执行全部在 worker 侧完成。

## 目录结构

```text
cmd/                # 三个进程入口
internal/sast/      # SAST：模型、存储、服务、handler、CodeQL 扫描器、worker
internal/dast/      # DAST：模型、存储、服务、handler、扫描器（nmap/nuclei）、worker
internal/config/    # .env 解析
internal/infra/     # PostgreSQL、Redis 连接
internal/webui/     # 前端产物内嵌与静态托管
web/                # Vue 3 前端源码
docs/               # 架构文档
```

## 运行依赖

| 依赖 | 用途 | 说明 |
| --- | --- | --- |
| Go 1.26 | 编译 | `go.mod` 指定 |
| PostgreSQL | 批次、任务、结果 | 建表 SQL 见下文 |
| Redis | 扫描任务队列与 worker 注册 | SAST 队列键 `sast:scan:queue`，DAST 队列键 `dast:tasks:<cluster>:<zone>:<template_version>` |
| CodeQL | SAST 扫描 | `CODEQL_PATH` 指向 `codeql` 可执行文件 |
| nmap、nuclei | DAST 扫描 | 只装在 worker 主机上，`DAST_NMAP_PATH`、`DAST_NUCLEI_PATH` |
| 模板目录 | DAST PoC | `DAST_TEMPLATE_ROOT` 下有 `catalog.json` 与模板文件 |

## 配置

所有进程共用项目根目录的 `.env`（`.env` 不入库），由 `internal/config` 的 `LoadEnv` 一次性解析；缺失报错，无默认值。

```dotenv
# server
APP_NAME=devsecops
SERVER_ADDR=127.0.0.1
SERVER_PORT=9000
WORKER_ID=

# postgres
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5432
POSTGRES_USER=codeql
POSTGRES_PASSWORD=codeql123
POSTGRES_DATABASE=devsecops

# redis
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=11

# SAST
CODEQL_PATH=/usr/local/bin/codeql
WORK_ROOT=internal/sast/result
QUERY_SUITE=security-extended

# DAST
DAST_NMAP_PATH=/usr/bin/nmap
DAST_NUCLEI_PATH=/usr/local/bin/nuclei
DAST_TEMPLATE_ROOT=/opt/dast/templates
DAST_RESULT_ROOT=internal/dast/result
DAST_CLUSTER_ID=production
DAST_NETWORK_ZONE=internal
```

扫描参数（模板集合、探测端口、速率、并发、超时）不属于环境配置，由创建任务时提交；心跳间隔、任务期限等属于程序内固定行为。

## 数据库

建表 SQL 由部署显式执行，程序不会自动建表。

```sql
-- SAST
CREATE TABLE sast_scans (
    id BIGSERIAL PRIMARY KEY,
    repo_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    error TEXT NOT NULL DEFAULT '',
    language TEXT NOT NULL DEFAULT '',
    timeout BIGINT NOT NULL DEFAULT 0,
    report_path TEXT NOT NULL DEFAULT '',
    commit_sha TEXT NOT NULL DEFAULT '',
    worker_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE sast_findings (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES sast_scans(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    level TEXT NOT NULL DEFAULT 'warning',
    security_score DOUBLE PRECISION CHECK (security_score IS NULL OR security_score BETWEEN 0 AND 10),
    cwes JSONB NOT NULL DEFAULT '[]'::jsonb,
    locations JSONB NOT NULL DEFAULT '[]'::jsonb,
    related_locations JSONB NOT NULL DEFAULT '[]'::jsonb,
    code_flows JSONB NOT NULL DEFAULT '[]'::jsonb,
    fingerprints JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (scan_id, ordinal)
);
CREATE INDEX idx_sast_findings_scan_id_id ON sast_findings(scan_id, id);

-- DAST
CREATE TABLE dast_assets (
    source_id TEXT NOT NULL,
    cmdb_id TEXT NOT NULL,
    host TEXT NOT NULL,
    cluster_id TEXT NOT NULL,
    network_zone TEXT NOT NULL,
    business_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    registered_services JSONB NOT NULL CHECK (jsonb_typeof(registered_services) = 'array'),
    PRIMARY KEY (source_id, cmdb_id)
);

CREATE TABLE dast_scans (
    id BIGSERIAL PRIMARY KEY,
    created_by TEXT NOT NULL,
    request_key TEXT NOT NULL,
    request JSONB NOT NULL,
    queue_expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (created_by, request_key)
);

CREATE TABLE dast_tasks (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES dast_scans(id) ON DELETE CASCADE,
    plan JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    worker_id TEXT NOT NULL DEFAULT '',
    execution_deadline TIMESTAMPTZ,
    result JSONB,
    error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);
CREATE INDEX idx_dast_tasks_scan_id ON dast_tasks(scan_id, id);

CREATE TABLE dast_findings (
    id BIGSERIAL PRIMARY KEY,
    task_id BIGINT NOT NULL REFERENCES dast_tasks(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    data JSONB NOT NULL,
    UNIQUE (task_id, ordinal)
);
```

## 启动

```bash
# 前端（产物输出到 internal/webui/dist，由 server 内嵌）
cd web && npm install && npm run build

# server：API + 前端，默认 0.0.0.0:9000
go run ./cmd/server

# SAST worker
go run ./cmd/worker-sast

# DAST worker
go run ./cmd/worker-dast
```

## API

SAST（`/api/v1`）：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/scans` | 创建扫描（仓库地址或源码 zip） |
| GET | `/scans` | 批次列表 |
| GET | `/scans/:id` | 批次详情 |
| DELETE | `/scans/:id` | 删除批次 |
| GET | `/scans/:id/findings` | 漏洞列表 |
| DELETE | `/scans/:id/findings` | 清空漏洞 |
| GET | `/workers` | worker 在线状态 |

DAST（`/api/v1/dast`）：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/assets` | 已保存的资产列表，支持按来源、集群、网络区域及业务筛选 |
| POST | `/assets` | 手动添加资产，来源与资产标识组合唯一 |
| POST | `/scans` | 创建批次（资产集合 + 扫描选项） |
| GET | `/scans` | 批次列表 |
| GET | `/scans/:id` | 批次详情与任务列表 |
| GET | `/tasks/:id` | 任务详情与结果 |
| GET | `/scans/:id/findings` | 漏洞列表 |
| GET | `/workers` | worker 在线状态 |

DAST 的页面接口需要请求头 `X-User-Id` 标识调用方，接入统一登录后替换 `cmd/server/main.go` 中的 `userID`。

## CVE / PoC 规则与生成

cvps1 已建立 `poc_cves`、`poc_products`、`poc_generations`、`poc_jobs` 四张表及任务互斥索引。

AI 生成仅在用户指定 CVE、点击“生成探测模板”后执行。同步 CVE、搜索 GitHub、打开页面或发现缺少 PoC 均不会自动触发 AI 生成。后台队列仅执行用户已提交的任务。

同步优先读取 GitHub 索引仓库：`nomi-sec/PoC-in-GitHub`、`trickest/cve`、`projectdiscovery/nuclei-templates`，再读取 GitHub 公告和 NVD。公告按日期范围获取，索引仓库按日期范围涉及的 CVE 年份导入；仓库索引在服务端缓存 6 小时。仓库只读取数据和模板链接，不执行其中的代码。各来源的链接按 URL 合并，人工补充不被同步覆盖。

后台任务持久化，单个任务依次执行。某个远程来源不可用时记录该来源错误，继续处理其他来源，最终显示“部分完成”及具体原因；数据库写入错误立即终止。近期公告中仍没有相关链接的 CVE 才逐个进行 GitHub 搜索，间隔 7 秒，搜索缓存 24 小时；手动搜索也会查询上述索引。服务重启时未完成任务标为中断，可重新提交。列表保留浏览器及服务端 5 分钟缓存。

PoC 生成页管理按产品复用的指纹档案，使用 CVE 来源数据、手工材料和产品档案抽取 `internal/poc/spec.schema.json` 定义的规格，再由 `agentPoc.go` 渲染为 Nuclei JSON 模板（JSON 同时是合法 YAML）。每批最多 20 个 CVE，结果逐项保存。缺少材料时记录 `needs-evidence`，不生成模板。规格可手动修改并重新渲染、下载；产物是产品指纹和版本探测草稿

`internal/infra/netAgent.go` 支持以下协议，Base URL 包含 API 版本路径：

| AI_PROTOCOL | AI_BASE_URL 示例 | 接口 |
| --- | --- | --- |
| openai | `https://api.openai.com/v1` 或兼容服务地址 | `/chat/completions` |
| anthropic | `https://api.anthropic.com/v1` | `/messages` |
| gemini | `https://generativelanguage.googleapis.com/v1beta` | `/models/{model}:generateContent` |

在 `.env` / `env_cvps1` 设置 `AI_PROTOCOL`、`AI_BASE_URL`、`AI_MODEL`、`AI_API_KEY`；缺少配置时可管理 CVE 和产品档案，生成接口明确报错。`GITHUB_TOKEN` 和 `NVD_API_KEY` 为可选数据源凭据，未设置时使用公开接口限额。密钥仅在服务端读取。配置变更后重启 server。

相关接口统一位于 `/api/v1/dast`，使用现有 `X-User-Id` 身份约定：`GET /pocs`、`PUT /pocs/:id`、`POST /pocs/sync`、`POST /pocs/search`、`GET /poc-jobs`、`GET/PUT /poc-products[/:key]`、`GET /poc-agent`、`POST /poc-generate`、`GET/PUT /poc-generations[/:id]`。

数据源接口：[NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities)、[GitHub 公告](https://docs.github.com/en/rest/security-advisories/global-advisories)、[GitHub 仓库搜索](https://docs.github.com/en/rest/search/search#search-repositories)。


### 从 CVE 自动生成

PoC 生成页输入 CVE 编号后，自动读取数据库中的描述、来源记录、相关链接、人工补充及匹配产品档案，预览不调用 AI。用户点击生成后，后台从这些信息识别产品、抽取规格并渲染探测模板；信息不足时保存原因，产品关联允许为空，不创建虚构档案。相关链接本身不代表已抓取正文。

页面“API 配置”支持 OpenAI 兼容、Anthropic 和 Gemini。设置保存到 server 工作目录的 `.env`（cvps1 为 `env_cvps1` 的符号链接），文件权限为 0600，立即用于后续任务，重启后仍有效。API 不返回密钥；密钥留空保留原值，切换协议或地址需重新填写。运行中的任务继续使用提交执行时的配置。

既有部署需执行 `ALTER TABLE poc_generations ALTER COLUMN product_key DROP NOT NULL;`，以保存尚未识别产品的生成结果。新增接口：`GET /api/v1/dast/poc-context/:id`、`PUT /api/v1/dast/poc-agent`。

日期同步支持跨月、跨年范围；后台将公告请求拆成最多 30 天的窗口，逐窗分页。日期格式或先后关系错误在提交时直接返回，不再创建必然失败的任务。

单个 CVE 查询优先使用已入库的官方记录；缺失时并行读取 CVEProject/cvelistV5、对应编号的 PoC-in-GitHub JSON 和 GitHub 公告，保存后供后续访问复用。它不等待整年同步任务，也不下载整年仓库。页面“更新来源”可重新获取该编号；来源不可用会显示具体信息。规则页也可输入完整编号后点击“按编号获取”。AI 生成仍由用户手动提交。
