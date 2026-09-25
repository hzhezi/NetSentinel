# NetSentinel 设计文档

> 准实时 NIDS 检测与研判平台：Suricata 规则检测 + 多智能体 LLM 研判 + Web 可视化
>
> 状态：已评审通过（2026-09-24）
> 交付形态：硕士专业实践（实践报告 + 现场答辩演示，各占约 50%）

---

## 1. 背景与定位

### 1.1 问题
传统 NIDS（Suricata / Snort 等）能高效检测已知攻击，但产出的是**原始告警**：数量大、误报多、缺乏上下文与解释，分析师需要大量人工研判。而近年出现的 LLM 安全运营（AI SOC）工作几乎都基于 **SIEM/主机日志（Wazuh 等）**，**不覆盖网络流量层**。

### 1.2 定位
构建一个平台，把**网络层规则检测**（Suricata）与 **LLM 智能研判**（多智能体协同）打通，形成一条从流量到可读结论的完整链路。

### 1.3 创新点（报告立论）
经开源调研（见 §12），"**网络流量检测 → LLM 研判**"这条交叉链路在开源生态中几乎空白：
- 做 NIDS 的（IntruShield / Watcher / Digger）没有 LLM 研判，或只有一句话解释；
- 做 LLM 研判的（SocTalk / Warren / DeepInv / AiSOC）全部基于 SIEM 日志，不碰 pcap 检测。

本项目的贡献即填补这一交叉点，并**给出定量评测**（现有开源项目普遍缺失）。

---

## 2. 目标与成功标准

### 2.1 成功标准（可验证）
| 维度 | 标准 |
|---|---|
| 系统 | `docker compose up` 一键启动；能加载 pcap 并产出告警 |
| 演示 | 现场上传 pcap → 告警按时间顺序流式涌出 → AI 研判卡片自动生成 → 可点开证据链 |
| 检测指标 | Suricata 规则在 pcap 上的告警产出情况（规则命中、去重后数量）|
| 研判指标 | LLM 研判在人工抽样的 50~100 条上给出误报识别准确率、解释质量评分、平均耗时与成本 |
| 工程 | 分层架构、类型安全、测试、CI、容器化、结构化日志齐全 |

### 2.2 非目标（明确排除，避免过度设计）
- ❌ 真实网卡实时抓包（架构预留接口，不做实现）
- ❌ 串联阻断（IPS）/ 自动防火墙联动
- ❌ 机器学习检测引擎（本项目定位是"现有 IDS + LLM 研判"，
     不训练流量分类模型；详见 §2.12 决策记录）
- ❌ 多租户、OAuth、Kafka、K8s、微服务拆分
- ❌ 规则热更新与在线学习

---

## 3. 总体架构

```
┌──────────────────────────── 数据层 ────────────────────────────┐
│  带攻击的 pcap（演示 + 检测）                                    │
│  可选：CICIDS2017 的 pcap（真实攻击流量）                        │
└───────────────────────────────┬────────────────────────────────┘
                                ↓
┌──────────────────────── 输入 / 采集层 ──────────────────────────┐
│  Feeder（统一 Source 接口，支持倍速 / 暂停 / 断点）               │
│    ├─ EveFeeder   ：Suricata eve.json，按时间戳节奏重放（主路径） │
│    └─ (预留) LiveFeeder：网卡抓包                                │
└───────────────────────────────┬────────────────────────────────┘
                                ↓
┌───────────────────────── 检测层 ───────────────────────────────┐
│  Suricata 规则引擎（离线跑 pcap → eve.json）                     │
│              ↓  解析 + 归一化                                    │
│         Unified Alert（统一告警模型）                            │
│   去重（TTLCache）+ 抑制规则过滤 + 严重度映射 + 富化（GeoIP）      │
└───────────────────────────────┬────────────────────────────────┘
                                ↓
┌──────────────── 研判层（LangGraph 多智能体）────────────────────┐
│   [Triage Agent]  ──条件边──→  [Investigation Agent]            │
│     L1 快速分诊                  L2 工具驱动深度调查              │
│     (便宜模型)                   (强模型 + 工具 + evidence trail) │
│                      ↓                                          │
│                   [Persist]  →  END                             │
│   （可选）[Human Review]：interrupt 挂起，人工确认                │
│   独立任务：[Report Agent] 定时 / 手动生成安全日报               │
└───────────────────────────────┬────────────────────────────────┘
                                ↓
┌──────────────────── 存储层（PostgreSQL + Redis）────────────────┐
│  alerts / alert_enrichment / triage_results / suppression_rules │
│  evaluation_runs / users / audit_logs                           │
│  LangGraph checkpoint 表（PostgresSaver 自建）                   │
│  Redis：告警总线（Streams）+ 任务队列 + LLM 结果缓存              │
└───────────────────────────────┬────────────────────────────────┘
                                ↓
┌──────────────────────── 展示层（Web）──────────────────────────┐
│  Dashboard / 实时告警流 / 告警详情+证据链 / 研判评测 / 日报      │
│  WebSocket 实时推送                                             │
└─────────────────────────────────────────────────────────────────┘
```

### 分层原则
- **LangGraph 只出现在研判层**；检测层、存储层、展示层与它解耦。
- 检测层与展示层通过 **Redis Streams 告警总线**解耦（或直接经 service 层发布）。
- 展示层只消费统一告警与研判结果，不感知引擎细节。

---

## 4. 数据源与数据流

### 4.1 数据源
| 用途 | 内容 | 大小 |
|---|---|---|
| 检测 + 演示 | 带攻击的 pcap（CICIDS2017 的 pcap 版本，或其他公开样本）| 几百 MB |
| 降级来源 | Kaggle / HuggingFace 镜像的小样本 pcap | — |

下载策略：官方源为美国 UNB 服务器，国内可能不可达；**HuggingFace 亦被墙，用 `hf-mirror.com` 镜像**（实测可用）。

### 4.2 数据通路
```
pcap ──suricata -r──→ eve.json ──EveFeeder（按时间戳重放）──→ 统一告警 → 研判层
```
检测只经规则引擎一路，下游（去重/抑制/富化/研判/存储/推送）统一。

### 4.3 流式演示机制（关键技术点）
- Suricata 支持离线读取 pcap：`suricata -r demo.pcap -l ./logs`，输出的 `eve.json` **每条事件带原始时间戳**。
- `EveFeeder` 读取 `eve.json`，依据时间戳间隔（可乘倍速系数）逐条发出，复现"实时"节奏。
- 效果：告警按真实攻击发生顺序一条条流出，具备实时 IDS 观感，**无需网卡、无需 root、无需靶场**。
- **保底方案**：`DemoSimulator` 直接注入内置样例告警，保证演示永不空场。
- **live 与 replay 行为分离**：replay 不触发对外 webhook，仅 live 触发。

---

## 5. 检测层设计

### 5.1 统一告警模型 Unified Alert
```python
class UnifiedAlert:
    id: UUID
    source_engine: Literal["suricata"]
    detected_at: datetime  # 事件原始时间戳
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    protocol: str | None
    signature: str         # Suricata 签名文本
    attack_type: str | None  # 归一化攻击类型
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: float      # 由 Suricata priority 映射而来
    category: str | None
    raw: dict              # 原始 eve 事件（jsonb）
    dedup_key: str
    status: Literal["new", "triaged", "escalated", "closed", "suppressed"]
```

> 设计说明：`source_engine` 与 `confidence` 等字段保留为通用形式，
> 是为了将来若接入其他检测引擎时，下游管道无需改动。

### 5.2 Suricata 规则引擎
- **运行**：Docker 内 `suricata -r <pcap>`，输出 `eve.json`。
- **规则**：自定义规则集（覆盖 SSH 暴力破解、SQL 注入、Nmap 扫描、Log4Shell、XSS、反弹 shell、DNS 隧道、ICMP 扫描、目录穿越等），可扩充 ET 规则集。
- **解析**：`EVEParser` 将 eve 行解析为类型化对象（不因脏数据崩溃，返回 None）。
- **严重度映射**：Suricata priority → 平台 severity，并对语义较弱的 category 做 override。

### 5.3 告警处理管道
1. **去重**：`TTLCache(maxsize, ttl=60s)`，key = `src_ip + signature`，防告警风暴。
2. **抑制**：匹配 `suppression_rules`（sig_id / src_ip / category 的 AND 逻辑 + 可选过期），命中则丢弃；规则列表带 30s 内存缓存（热路径友好）。
3. **富化**：GeoIP（国家/城市/经纬度/组织）等。
4. **归一化**：转为 `UnifiedAlert`。
5. **发布**：写库 + 发 Redis Stream + WS 广播。

---

## 6. 研判层设计（LangGraph 多智能体）

### 6.1 图结构
```
START
  ↓
[triage]                    # Triage Agent（L1）
  ↓  add_conditional_edges（读 verdict.escalate + 硬规则）
  ├── escalate=false ────────────────────────────┐
  └── escalate=true ──→ [investigate]            │  # Investigation Agent（L2）
                          （工具调用循环）          │
                          ↓                        │
                       [persist] ←─────────────────┘
                          ↓
                         END
（可选）[human_review]：interrupt 挂起等待人工确认，用于高影响动作
```
- `Report Agent` **不在主图内**，作为独立定时/手动任务（避免图变脏）。

### 6.2 Triage Agent（L1，轻量）
- 模型：便宜快速模型（如 `deepseek-chat`）。
- 触发：**每条**统一告警。
- 工具：`lookup_mitre_technique`、`count_related_alerts`（可选）。
- 输出（强制结构化）：
```json
{
  "verdict": "true_positive | false_positive | needs_human_review",
  "severity": "critical|high|medium|low",
  "confidence": 0-100,
  "escalate": true,
  "attack_type": "...",
  "summary": "2-3 句",
  "mitre_techniques": ["T1110"],
  "recommended_actions": ["..."]
}
```

### 6.3 Investigation Agent（L2，工具驱动）
- 模型：强推理模型（如 `deepseek-reasoner`）。
- 触发：`escalate=true` 或人工点「深度调查」。
- 机制：ReAct 风格工具循环，**自研节点**（不用 `create_react_agent` 黑盒），迭代上限（如 10 轮），**最后一轮强制 `submit_verdict`**，保证始终产出结构化结果。
- 产出：结论 + **evidence trail**（每步推理、工具调用与结果），可审计、可回放。

### 6.4 System Prompt 铁律（借鉴 copilot，防幻觉）
- 只引用告警或工具结果中的证据；**查不到视为"未知"，而非"安全"**。
- `needs_human_review` 是一等结论，不是失败。
- **不得凭记忆写 MITRE 编号**，必须经 `lookup_mitre_technique` 查表。
- 严重度用自己的判断，不直接抄检测层上报值。

### 6.5 Report Agent
- 模型：便宜模型。触发：定时（如每小时）/ 手动。
- 输入：时间窗内统计 + 重点事件摘要。输出：可读安全日报。

### 6.6 成本与可靠性控制
- **结果缓存**：同一 `sig_id` 的研判结果缓存（Redis / DB），不重复调用。
- **按 `sig_id` 去重**：后台对新签名只自动研判一次。
- **token 计量**：每次调用记录 prompt/completion token，出成本报表。
- **失败重试 + 降级**：API 失败重试；最终失败标记 `needs_human_review` 并记录。
- **结构化校验**：输出经 Pydantic 校验，不合规则重试。

---

## 7. 工具契约

### 7.1 Investigation Agent 工具
| 工具 | 输入 | 输出 | 说明 |
|---|---|---|---|
| `lookup_ip_reputation` | `ip` | 信誉/滥用分/地理位置/ISP/是否已知恶意 | 先查本地情报库；可开关接 AbuseIPDB/OTX |
| `get_related_alerts` | `field`, `value` | 关联告警列表 | field ∈ {src_ip,dst_ip,signature,attack_type}，识别多步攻击 |
| `get_alert_detail` | `alert_id` | 原始 eve / flow 记录 | 载荷、协议细节 |
| `lookup_mitre_technique` | `behavior` | 匹配的 technique id/名称 | **本地映射表，防幻觉** |
| `check_suppression` | `sig_id`,`src_ip`,`category` | 是否命中抑制规则 | "已知噪声"判断 |
| `get_asset_context` | `ip` | 资产类型/角色 | 判断严重度的关键上下文（数据不足时用规则近似）|
| `submit_verdict` | 结构化字段 | — | 强制终态输出 |

### 7.2 工具实现原则（借鉴 copilot）
- 工具的**签名与真实 API 包装一致**，便于日后替换真实服务。
- 开发/演示阶段可用**本地 mock/样例数据**，保证演示不因网络失败而中断。

---

## 8. 存储设计（PostgreSQL）

| 表 | 关键字段 | 说明 |
|---|---|---|
| `alerts` | id, source_engine, detected_at, src/dst, signature, severity, confidence, raw(jsonb), status, dedup_key | 统一告警，含时间与严重度复合索引 |
| `alert_enrichment` | alert_id, geo_*, ti_* | 富化信息 |
| `triage_results` | alert_id, agent, verdict, severity, confidence, summary, mitre(jsonb), actions(jsonb), evidence_trail(jsonb), tokens, latency_ms | 研判结果与证据链 |
| `suppression_rules` | id, name, sig_id, src_ip, category, reason, expires_at, enabled | 抑制规则 |
| `evaluation_runs` | id, kind, dataset, params(jsonb), metrics(jsonb), created_at | 评测记录 |
| `users` | id, username, password_hash, role | 认证与 RBAC |
| `audit_logs` | id, actor, action, target, detail, created_at | 审计 |
| LangGraph checkpoint 表 | — | 由 `PostgresSaver.setup()` 自动创建 |

---

## 9. 后端设计

### 9.1 分层（借鉴 IntruShield DDD）
```
backend/
├── api/v1/routes/        # 路由层：零业务逻辑
├── api/websocket/        # WS 连接管理与广播
├── services/             # 领域逻辑：alert / rule / evaluation / report
├── repositories/         # 数据访问：Unit of Work + AsyncSession
├── models/               # SQLAlchemy ORM
├── schemas/              # Pydantic 出入参
├── detection/            # eve_parser / feeders / alert_pipeline / ml_engine / suricata_runner
├── agents/               # LangGraph 图、节点、prompts、tools
├── core/                 # config / logging / event_bus / exceptions / security
├── middleware/           # rate limiter / request logger / error handler
└── workers/              # 异步任务：重放、批量评测、日报
```

### 9.2 关键组件
- **EventBus**：轻量 pub/sub，异步 handler 支持协程或线程。
- **WebSocketManager**：连接集合 + 锁；广播时快照，发送失败即剔除 stale 连接；消息格式 `{type, timestamp, data}`。
- **配置**：`pydantic-settings`，`.env` 加载；密钥只经环境变量（**不入库、不入仓库**）。
- **中间件**：限流、请求日志、统一异常处理。
- **生命周期**：FastAPI `lifespan` 启动后台任务，关闭时优雅取消。

### 9.3 API（节选）
```
POST /api/v1/feeds/replay         启动重放（数据集、倍速、引擎）
POST /api/v1/feeds/stop
GET  /api/v1/alerts               分页 / 过滤 / 搜索
GET  /api/v1/alerts/{id}          详情（含富化、研判、证据链）
POST /api/v1/alerts/{id}/investigate   触发深度调查（L2）
POST /api/v1/alerts/{id}/suppress      创建抑制规则
GET  /api/v1/statistics/*         仪表盘统计
POST /api/v1/evaluation/run       触发评测任务
GET  /api/v1/evaluation/{id}      评测结果
GET  /api/v1/reports/daily        日报
WS   /ws/events                   实时告警与研判推送
```

---

## 10. 前端设计

- **技术栈**：React + TypeScript + Vite + Ant Design + ECharts。
- **状态**：TanStack Query（服务端状态）+ Zustand（本地/实时状态）。
- **实时**：WebSocket hook，指数退避重连（1s → 32s）；新告警插入 store，按 id 去重，缓冲上限防内存泄漏（如 1000 条）；按 slice 订阅减少重渲染。
- **页面**：
  - **Dashboard**：KPI 卡片、流量/告警时间线、严重度分布、Top 攻击源。
  - **Alerts**：实时告警流 + 过滤/搜索/分页 + 状态流转。
  - **Alert Detail**：原始事件、富化信息、AI 研判卡片、**证据链时间线**、「深度调查」按钮。
  - **Feed Control**：选择 pcap、倍速，开始/暂停重放。
  - **Evaluation**：LLM 研判评测结果（一致率 / 耗时 / 成本）。
  - **Reports**：安全日报。
  - **Settings**：抑制规则、AI 开关与模型选择、API Key 状态。

---

## 11. 评测方案（报告核心）

### 11.1 规则检测（定性 + 可得处定量）
- 在 pcap 上运行 Suricata，统计规则命中情况、去重前后告警数量。
- 说明规则引擎的能力边界（只能覆盖已知攻击）。

### 11.2 LLM 研判（定量 + 定性）
- 人工抽样 50~100 条告警作为评测集（含真实标签）。
- 指标：**误报识别准确率**、verdict 与人工判断一致率、MITRE 映射正确率、解释质量人工打分（1~5）。
- 成本：平均 token 与费用；**Analyst time saved**（按行业均值 20 分钟/告警估算）。

### 11.4 系统（工程）
- 端到端延迟、重放吞吐、WS 推送延迟。

> 所有评测结果落 `evaluation_runs` 表，前端可视化，报告直接引用。

---

## 12. 技术栈

| 层 | 选型 |
|---|---|
| 前端 | React 18 + TypeScript + Vite + Ant Design + ECharts + TanStack Query + Zustand |
| 后端 | Python 3.12 + FastAPI + Pydantic v2 + SQLAlchemy 2.0(async) + Alembic |
| 检测 | Suricata 7（Docker）|
| 研判 | LangGraph（自定义节点）+ DeepSeek API（chat / reasoner） |
| 存储 | PostgreSQL 16 + Redis 7 |
| 异步 | Redis Streams（告警总线）+ ARQ/Celery（重放、评测、日报） |
| 可观测 | structlog 结构化日志 + `/health` + `/metrics`(Prometheus) |
| 测试 | pytest + Vitest + Playwright |
| 质量 | ruff + mypy + eslint + prettier + pre-commit |
| 部署 | docker-compose（api / worker / web / db / redis / suricata）+ Nginx |
| CI | GitHub Actions |

> LangSmith：默认关闭（数据外发）。需要调试/出报告截图时，用环境变量临时开启。

---

## 13. 分期计划

### 期 1：基础闭环（保底可交付）
- Suricata 集成（Docker）+ 自定义规则集
- EVE 解析 + EveFeeder 按时间戳重放
- 统一告警模型 + 去重
- Triage Agent（L1）+ 结构化输出
- PostgreSQL + 基础 API + Web 实时告警流
- **里程碑：上传 pcap → 告警流式涌出 → 每条出 AI 分诊卡片**

### 期 2：深度调查
- 抑制规则、GeoIP 富化
- Investigation Agent（L2）+ 工具集 + evidence trail
- Human Review（interrupt）+ 「深度调查」按钮
- **里程碑：可点开的完整证据链**

### 期 3：评测与打磨
- LLM 研判人工评测集与结果页
- Report Agent + 日报
- 演示脚本、录屏备份、Docker 一键启动
- 报告素材整理
- **里程碑：报告数据齐备，演示可稳定复现**

---

## 14. 风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| pcap 样本下载受阻 | 阻塞 | 用 hf-mirror.com 镜像；备选 Kaggle 或公开恶意流量样本站 |
| LLM 输出不稳定 | 研判不可用 | 强制结构化 + Pydantic 校验 + 重试 + 缓存 |
| API 成本/限流 | 费用与失败 | 缓存 + 按 sig_id 去重 + 分层（多数走便宜模型）+ 计量 |
| 演示现场翻车 | 答辩失败 | DemoSimulator 保底 + 录屏备份 + 一键启动脚本；replay 与 live 行为分离 |
| LangGraph 版本变动 | 编译/运行异常 | 锁定稳定版本，不中途升级 |
| 范围蔓延 | 无法按时交付 | 严守 §2.2 非目标；分期保证任何时刻有完整可交付物 |

---

## 15. 借鉴来源与 License 说明

| 来源 | License | 借鉴内容 | 处理方式 |
|---|---|---|---|
| **IntruShield NIDS** | MIT | 分层 DDD 骨架、EVE tail 管道、EventBus、WSManager、TTLCache 去重、DemoSimulator、Suricata 规则写法 | 可借鉴代码，**注明来源** |
| **alert-triage-copilot** | MIT | 强制结构化 verdict、evidence trail、工具契约、prompt 铁律、time-saved 指标、mock 数据保底 | 可借鉴代码，**注明来源** |
| **Watcher IDS** | **AGPL-3.0** | LLM 结果缓存、token 计量、抑制规则、replay 不触发 webhook | **只借鉴设计，不复制代码** |
| **SocTalk / DeepInv / AiSOC / Warren** | Apache-2.0 / 其他 | 分层 Agent 编排思路、SOC L1/L2 分级类比 | 仅作思路参考 |

> **知识产权切割**：若本项目申请软著或发表论文，所有借鉴点将**重写实现**，并在文档中做明确来源说明与切割。

---

## 15.5 关键决策：为什么不做机器学习检测

**决策**：检测层只使用 Suricata 规则引擎，**不训练流量分类模型**。

**背景**：项目曾一度纳入"规则 + ML 双引擎"设计，并完成了 CICIDS2017
的数据准备、XGBoost 训练与严格评估。后经重新确认项目定位，**将该部分整体移除**。

**理由**：
1. **项目定位是"在现有 IDS 之上加 LLM 研判"**，核心价值在于研判层对原始告警的
   增值（误报过滤、解释、关联、处置建议），而非另造一个检测器。
2. **实测数据显示 ML 检测的边际价值有限**：在按攻击类型留一验证（模拟零日）下，
   平均检出率仅 10.74%（DDoS 21.45%、PortScan 0.03%），而随机切分下的
   99.99% F1 是 CICIDS2017 已知的评估虚高所致。
   换言之，该模型无法真正弥补规则引擎"只能抓已知攻击"的短板。
3. **聚焦**：双引擎会引入特征管道、模型版本管理、推理服务等额外复杂度，
   而收益与该复杂度不成比例。

**保留的认知**（若将来需要重新评估）：
- CICIDS2017 在随机切分下可轻易达到 99.9%+ F1，但这是**已知的评估虚高**，
  报告数字时必须同时说明其局限，不得包装为模型能力强。
- 若要真正做流量层面的未知攻击检测，代价是：需要跨流/会话级特征
  （单条流的 78 维特征本质上无法表达"同一源访问了多少端口"），
  以及按攻击类型分组或时间切分的严格评估流程。

---

## 16. 待办 / 开放问题

- [ ] 数据集实际下载情况确认（镜像可用性）
- [ ] DeepSeek function calling 在 LangGraph 自定义节点中的接入细节验证
- [ ] `get_asset_context` 的资产数据来源（mock 表 or 规则近似）
- [ ] LangGraph 版本锁定确认
- [ ] 演示 pcap 选型（哪段 CICIDS 流量最适合现场演示）
