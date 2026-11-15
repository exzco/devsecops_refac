# AGENT.md

本仓库 AI Agent 的强制执行规范，优先级高于任何默认工作习惯。

**核心原则**：修改代码后仅执行 `go test ./...` `go vet ./...` 与 `go build ./...`，三者通过即结束本轮任务。

## 1. 验证上限

唯一允许执行的验证命令（此为**上限**，非下限）：

```powershell
go vet ./...
go test ./...
go build ./...
```

- **禁止加码**：禁止以“保险起见”增加任何额外验证步骤。
- **交付标准**：只需说明**修改了哪些文件、为何修改**；无需汇报验证过程、基线状态或验收项。

## 2. 禁止的防御性流程

以下流程仪式全部禁止，不得执行，不得变相绕过：

| 禁止项           | 禁止范围                                                     |
| :--------------- | :----------------------------------------------------------- |
| **探针**         | 不新建 `lab/` 调试程序、一次性验证工具、回显服务或探针脚本。 |
| **快照**         | 不保存改动前状态副本、前后对比物或任何中间态文件。           |
| **基线**         | 不建立“唯一基线”、基线版本或基线哈希，不做改动前全面盘点。   |
| **可追溯备份**   | 不为“可回滚”而复制文件、另存版本、留档或归档。               |
| **证据**         | 不产出“证据”“证明”“实测记录”“验证记录”等文档；代码本身即说明。 |
| **门禁**         | 不建立门禁机制、检查点、门禁脚本或准入检查。                 |
| **夹具**         | 不新建 `testdata`、fixture 或测试数据文件。                  |
| **哈希校验**     | 不做哈希比对、不加哈希校验步骤、不维护校验清单。             |
| **冒烟测试**     | 不写冒烟用例、不跑冒烟套件、不做“先冒烟再全量”。             |
| **分阶段改造**   | 不拆分为“阶段 A → B → C”来控险，一次改到位。                 |
| **全量 dry-run** | 上线或收工前不做全量空跑。                                   |
| **验收矩阵**     | 不制作验收矩阵、验收表或验收清单。                           |

> **原因**：上述流程将常规代码修改异化为高成本仪式，消耗时间与注意力。关注点应始终锁定在代码本身，而非外围流程。

## 3. 禁止的代码退化模式

修改代码时必须遵守以下实现约束，防止结构性熵增：

| 禁止项                   | 约束要求                                                     |
| :----------------------- | :----------------------------------------------------------- |
| **静默吞错与防御性兜底** | 遵循 Fail-Fast；禁止捕获异常后仅打日志继续执行，禁止对缺失字段或契约违约私自填充默认值。 |
| **增量补丁堆叠**         | 新增边界条件时优先统一现有数据结构或控制流，禁止通过外挂 `if/else` 特判或新增布尔标志位（`isXxx`、`forceYyy`）打补丁。 |
| **冗余衍生状态**         | 坚持单一数据源（SSOT）；禁止在多处重复存储同一事实并手动同步状态。 |
| **过度抽象与包装**       | 禁止为单次调用逻辑引入无实质价值的 Wrapper、工厂类或空壳接口。 |
| **规避检查**             | 遇编译或静态检查报错时必须修复根因，禁止使用类型强转、`_ = err`、`//nolint` 或注释代码绕过。 |
| **无授权范围蔓延**       | 保持最小 Diff 边界；严禁顺手修改无关文件的格式、注释、命名或引入未请求的新依赖。 |

## 4. 推荐设计模式与重构示例
### 4.1 表驱动设计 / 函数映射表（替代分支膨胀）

- **问题示例**：需求增加时不断追加 `if/else` 或 `switch` 分支，分发骨架被重复修改。

```go
func dispatch(kind string, p Payload) error {
    if kind == "email" {
        return sendEmail(p)
    } else if kind == "sms" {
        return sendSMS(p)
    } else if kind == "webhook" {
        return postWebhook(p)
    }
    return fmt.Errorf("unknown kind: %s", kind)
}
```

- **示例代码**：用映射表收敛分发逻辑，新增渠道仅追加一条映射，零侵入分发函数。

```go
var dispatchers = map[string]func(Payload) error{
    "email":   sendEmail,
    "sms":     sendSMS,
    "webhook": postWebhook,
}

func dispatch(kind string, p Payload) error {
    fn, ok := dispatchers[kind]
    if !ok {
        return fmt.Errorf("unknown kind: %s", kind)
    }
    return fn(p)
}
```

### 4.2 显式状态转移表（替代布尔标志位组合）

- **问题示例**：用多个独立布尔字段描述生命周期，导致非法中间态与嵌套判空。

```go
type Order struct {
    IsPaid      bool
    IsShipped   bool
    IsCancelled bool
}

func ship(o *Order) error {
    if o.IsCancelled || !o.IsPaid || o.IsShipped {
        return errors.New("cannot ship")
    }
    o.IsShipped = true
    return nil
}
```

- **示例代码**：用单一 `State` 枚举与转移表定义合法迁移，根除非法状态组合。

```go
type transitionKey struct {
    from  OrderState
    event OrderEvent
}

var transitions = map[transitionKey]OrderState{
    {StateCreated, EventPay}:    StatePaid,
    {StatePaid, EventShip}:      StateShipped,
    {StateCreated, EventCancel}: StateCancelled,
}

func applyEvent(cur OrderState, ev OrderEvent) (OrderState, error) {
    next, ok := transitions[transitionKey{cur, ev}]
    if !ok {
        return cur, fmt.Errorf("invalid transition: %s -> %s", cur, ev)
    }
    return next, nil
}
```

### 4.3 扁平管道（替代多层 Wrapper 嵌套）

- **问题示例**：通过多层结构体装饰器包装调用链，上下文传递与执行顺序隐式分散。

```go
handler := &MetricsWrapper{
    next: &AuthWrapper{
        next: &RateLimitWrapper{
            next: coreHandler,
        },
    },
}
```

- **示例代码**：用函数切片顺序执行，流程扁平且短路退出明确。

```go
type Step func(context.Context, *Request) error

func runPipeline(ctx context.Context, req *Request, steps ...Step) error {
    for _, step := range steps {
        if err := step(ctx, req); err != nil {
            return err
        }
    }
    return nil
}
```

### 4.4 Functional Core, Imperative Shell（隔离纯逻辑与 I/O 副作用）

- **问题示例**：数据库查询、当前时间读取与业务规则混杂在同一函数内，耦合全局状态。

```go
func applyDiscount(ctx context.Context, db *sql.DB, orderID string) error {
    var total int
    if err := db.QueryRowContext(ctx, "SELECT total FROM orders WHERE id=$1", orderID).Scan(&total); err != nil {
        return err
    }
    if time.Now().Weekday() == time.Friday && total > 100 {
        total = int(float64(total) * 0.9)
    }
    _, err := db.ExecContext(ctx, "UPDATE orders SET total=$1 WHERE id=$2", total, orderID)
    return err
}
```

- **示例代码**：纯函数内核只处理输入值计算，外层 Shell 集中承担 I/O 读写。

```go
// Functional Core：无 I/O、无副作用
func calcDiscount(total int, weekday time.Weekday) int {
    if weekday == time.Friday && total > 100 {
        return total * 9 / 10
    }
    return total
}

// Imperative Shell：仅负责 I/O 编排
func applyDiscount(ctx context.Context, db *sql.DB, orderID string, now time.Time) error {
    total, err := loadOrderTotal(ctx, db, orderID)
    if err != nil {
        return err
    }
    return saveOrderTotal(ctx, db, orderID, calcDiscount(total, now.Weekday()))
}
```

### 4.5 消费方最小接口（替代大而全的实现方接口）

- **问题示例**：在实现包预定义庞大接口，强迫调用方与测试桩背负无关方法。

```go
// 定义在 store 包，包含 10+ 方法
type UserStore interface {
    GetUser(ctx context.Context, id string) (*User, error)
    SaveUser(ctx context.Context, u *User) error
    DeleteUser(ctx context.Context, id string) error
    GetToken(ctx context.Context, id string) (string, error)
    // ...
}
```

- **示例代码**：在消费方按实际依赖定义 1–2 个方法的最小接口。

```go
// 定义在 auth 包，仅声明所需行为
type tokenReader interface {
    GetToken(ctx context.Context, id string) (string, error)
}

func verifySession(ctx context.Context, store tokenReader, id string) error {
    _, err := store.GetToken(ctx, id)
    return err
}
```

### 4.6 显式 Config Struct + Validate（替代长参数列表与 Builder）

- **问题示例**：超长位置参数列表或冗余 Builder 链式调用，缺少集中校验且易静默用零值。

```go
func NewClient(host string, port int, timeoutSec int, maxRetry int, useTLS bool) *Client {
    if timeoutSec == 0 {
        timeoutSec = 5 // 静默兜底掩盖调用方遗漏
    }
    return &Client{host: host, port: port, timeout: timeoutSec, retry: maxRetry, tls: useTLS}
}
```

- **示例代码**：使用显式配置结构体与 `Validate()`，缺失必填项立即 Fail-Fast。

```go
type ClientConfig struct {
    Host    string
    Port    int
    Timeout time.Duration
}

func (c ClientConfig) Validate() error {
    if c.Host == "" || c.Port <= 0 || c.Timeout <= 0 {
        return errors.New("invalid client config: host, port, and timeout are required")
    }
    return nil
}

func NewClient(cfg ClientConfig) (*Client, error) {
    if err := cfg.Validate(); err != nil {
        return nil, err
    }
    return &Client{cfg: cfg}, nil
}
```

### 4.7 结构化并发 Fan-out / Fan-in（替代裸 `go func()`）

- **问题示例**：循环内直接启动无监管协程，缺失取消传播、错误回传与并发上限控制。

```go
func fetchAll(urls []string) [][]byte {
    var res [][]byte
    var mu sync.Mutex
    for _, u := range urls {
        go func(url string) {
            b, _ := httpGet(url) // 吞错且无法感知完成与超时
            mu.Lock()
            res = append(res, b)
            mu.Unlock()
        }(u)
    }
    return res // 协程未结束即返回
}
```

- **示例代码**：使用 `errgroup.WithContext` 绑定生命周期与并发上限，按索引写入免锁切片。

```go
func fetchAll(ctx context.Context, urls []string) ([][]byte, error) {
    res := make([][]byte, len(urls))
    g, ctx := errgroup.WithContext(ctx)
    g.SetLimit(8)

    for i, u := range urls {
        g.Go(func() error {
            b, err := httpGet(ctx, u)
            if err != nil {
                return err
            }
            res[i] = b
            return nil
        })
    }
    if err := g.Wait(); err != nil {
        return nil, err
    }
    return res, nil
}
```

## 5. 边界：Agent 行为 vs. 产品逻辑

本规范仅约束 **Agent 修改代码的工作方式**，不改变**产品运行时的安全与校验机制**：

- **保留产品功能**：工具分发的完整性校验（主密钥派生 MAC）、凭据库加密落盘、算子令牌恒定时间比较等属于产品逻辑，严禁因本规范禁止“哈希/校验”而将其删除。
- **冻结历史产物**：仓库中已有的测试文件、`lab/` 探针与 `testdata` 夹具属于历史产物——**不删除**（除非明确要求），但**不运行、不扩展、不新增**。

## 6. 标准工作流

1. **读懂目标代码**（唯一值得投入时间的环节）。
2. **一次改到位**（不拆分阶段，不堆叠补丁）。
3. **执行 `go test ./...`  `go vet ./...` 与 `go build ./...`**（报错则直接修复至通过，禁止绕过、加豁免或注释）。
4. **收工汇报**：简述改动文件与原因。

## 7. 例外条款

仅当**用户明确指令**执行某项被禁操作时方可破例，且严格限于该单一指令本身。