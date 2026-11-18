# DevSecOps

SAST与DAST漏洞扫描平台：一个 HTTP 服务提供 API，两个 worker 分别执行代码扫描与资产扫描，结果统一落在 PostgreSQL。

## 组成

| 组件 | 入口 | 职责 |
| --- | --- | --- |
| server | `cmd/server/main.go` | HTTP API 与内嵌前端；批次、任务、结果的查询与编排 |
| worker-sast | `cmd/worker-sast/main.go` | 消费 SAST 队列，用 CodeQL 扫描源码仓库 |
| worker-dast | `cmd/worker-dast/main.go` | 消费 DAST 队列，用 nmap + nuclei 扫描资产 |
| web | `web/` | Vue 3 前端，构建产物由 `internal/webui` 内嵌进 server |

```bash
cd web && npm run build && go build -o server ./cmd/server && go build -o worker-sast ./cmd/worker-sast && go build -o worker-dast ./cmd/worker-dast

nohup ./server > server.log 2>&1 & nohup ./worker-sast > worker-sast.log 2>&1 & nohup ./worker-dast > worker-dast.log 2>&1 &

pkill -f "./server" || true; pkill -f "./worker-sast" || true; pkill -f "./worker-dast" || true
```
SAST 部分基于 codeql , DAST 部分使用 nmap nuclei 二进制来实现服务探测，POC 验证，没有使用 SDK 因为引入 SDK 使得编译出来的二进制程序过大。poc 部分，基于 github nvd 等数据源获取相关信息，nuclei yaml 生成部分，先查询数据源是否存在 yaml，若否则通过采集 cve 信息作为上下文，尝试通过 AI 生成相关 poc yaml ，需验证。可以通过 fofa 等测绘平台查询相关服务进而验证（注意不要影响正常服务运行）。
worker 直连 PostgreSQL 与 Redis：server 只负责 API 与编排，扫描执行全部在 worker 侧完成。大致页面如下
![alt text](./docs/image.png)
![alt text](./docs/image-1.png)
![alt text](./docs/image-2.png)
![alt text](./docs/image-3.png)
![alt text](./docs/image-4.png)
![alt text](./docs/image-5.png)
![alt text](./docs/image-6.png)

## 运行依赖

| 依赖 | 用途 | 说明 |
| --- | --- | --- |
| Go 1.26 | 编译 | `go.mod` 指定 |
| PostgreSQL | 批次、任务、结果 | 建表 SQL 见下文 |
| Redis | 扫描任务队列与 worker 注册 | SAST 队列键 `sast:scan:queue`，DAST 队列键 `dast:tasks:<cluster>:<zone>:<template_version>` |
| CodeQL | SAST 扫描 | `CODEQL_PATH` 指向 `codeql` 可执行文件 |
| nmap、nuclei | DAST 扫描 | 只装在 worker 主机上，`DAST_NMAP_PATH`、`DAST_NUCLEI_PATH` |
| 模板目录 | DAST PoC | `DAST_TEMPLATE_ROOT` 下有 `catalog.json` 与模板文件 |


## 数据库

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

## 部分 API

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
