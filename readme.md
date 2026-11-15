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

所有进程共用项目根目录的 `.env`（`.env` 不入库），由 `internal/config` 的 `LoadEnv` 一次性解析；缺失或非法的值直接报错，不填默认值。

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
| GET | `/assets` | 资产列表（CMDB／SIEM 来源，尚未接入时返回未配置错误） |
| POST | `/scans` | 创建批次（资产集合 + 扫描选项） |
| GET | `/scans` | 批次列表 |
| GET | `/scans/:id` | 批次详情与任务列表 |
| GET | `/tasks/:id` | 任务详情与结果 |
| GET | `/scans/:id/findings` | 漏洞列表 |
| GET | `/workers` | worker 在线状态 |

DAST 的页面接口需要请求头 `X-User-Id` 标识调用方，接入统一登录后替换 `cmd/server/main.go` 中的 `userID`。
