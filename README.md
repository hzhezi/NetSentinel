<div align="center">

# NetSentinel

**准实时 NIDS 检测与研判平台**

双引擎检测（Suricata 规则 + ML 异常检测）· LangGraph 多智能体 LLM 研判 · 实时 Web 可视化

[![CI](https://github.com/hzhezi/NetSentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/hzhezi/NetSentinel/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

</div>

> ⚠️ **项目状态：开发中**。当前处于期 1（基础闭环）实现阶段，尚未达到可运行状态。
> 真实完成度见文末[进度](#进度)。

---

## 这是什么

传统 NIDS（Suricata / Snort）检测能力强，但产出的是**原始告警**：数量大、误报多、缺少上下文与解释，需要分析师大量人工研判。而现有的 LLM 安全运营方案几乎全部基于 **SIEM / 主机日志（Wazuh 等）**，不覆盖网络流量层。

NetSentinel 把**网络层检测**与 **LLM 智能研判**打通，形成一条从流量到可读结论的完整链路：

```
pcap / 数据集 ──→ 双引擎检测 ──→ 统一告警 ──→ 多智能体研判 ──→ Web 可视化
                  规则 + ML                  Triage / Investigation / Report
```

### 核心特性

- **双引擎检测**：Suricata 规则引擎（抓已知）+ ML 异常检测（抓未知），在**告警层**统一为 `UnifiedAlert`
- **准实时重放**：按原始时间戳节奏重放 pcap / 数据集，复现实时 IDS 观感，无需网卡/root/靶场
- **多智能体研判**：LangGraph 编排 L1 快速分诊 → L2 工具驱动深度调查，按 SOC 分级控制成本
- **证据可审计**：每次研判记录完整 evidence trail，结论可逐行追溯，不做黑盒
- **防幻觉约束**：强制结构化输出、MITRE 编号必须查表、查不到视为"未知"而非"安全"

---

## 架构

```
┌───────────────────────── 数据层 ─────────────────────────┐
│  CICIDS2017 特征 CSV（训练/评测） · 小段 pcap（演示）      │
└────────────────────────────┬─────────────────────────────┘
                             ↓
┌──────────────────────── 输入层 ──────────────────────────┐
│  CsvFeeder / EveFeeder（按时间戳重放）· (预留)LiveFeeder  │
└────────────────────────────┬─────────────────────────────┘
                             ↓
┌────────────────────── 检测层（双引擎）───────────────────┐
│  ML 分类器（XGBoost）  ·  Suricata 规则引擎              │
│            ↓ 归一化 → UnifiedAlert                       │
│  去重(TTLCache) · 抑制规则 · 富化(GeoIP)                 │
└────────────────────────────┬─────────────────────────────┘
                             ↓
┌────────────── 研判层（LangGraph 多智能体）───────────────┐
│  [Triage L1] ──条件边──→ [Investigation L2] → [Persist] │
└────────────────────────────┬─────────────────────────────┘
                             ↓
┌─────────────── 存储层（PostgreSQL + Redis）──────────────┐
│  alerts · triage_results · suppression_rules · 评测记录  │
└────────────────────────────┬─────────────────────────────┘
                             ↓
┌──────────────────────── 展示层（Web）───────────────────┐
│  实时告警流 · 研判卡片 · 证据链 · 评测报告 · WebSocket    │
└─────────────────────────────────────────────────────────┘
```

---

## 技术栈

| 层 | 选型 |
|---|---|
| 后端 | Python 3.13 · FastAPI · Pydantic v2 · SQLAlchemy 2.0 (async) · Alembic |
| 前端 | React 18 · TypeScript · Vite · Ant Design · TanStack Query · Zustand |
| 存储 | PostgreSQL 16 · Redis 7 |
| 检测 | Suricata 7（Docker）· scikit-learn / XGBoost |
| 研判 | LangGraph（自定义节点）· DeepSeek API |
| 可观测 | structlog（结构化 JSON）· Prometheus metrics |
| 质量 | pytest · ruff · mypy · Vitest · GitHub Actions |

---

## 快速开始

> 以下命令在**当前开发阶段**可用。完整的一键启动（含前端）在期 1 收尾时提供。

### 环境要求

- Python **3.13**（由 `.python-version` 固定，`uv` 会自动匹配）
- [uv](https://github.com/astral-sh/uv)（Python 包管理器）
- Docker Desktop（提供 PostgreSQL / Redis）
- Node.js 20+（前端，期 1 后段需要）

### 步骤

```bash
# 1. 克隆
git clone git@github.com:hzhezi/NetSentinel.git
cd NetSentinel

# 2. 配置环境变量
cp .env.example .env
# 编辑 .env，填入 DEEPSEEK_API_KEY（不带 key 也能启动，LLM 功能不可用）

# 3. 安装依赖
uv sync

# 4. 启动 PostgreSQL + Redis
docker compose up -d db redis
docker compose ps                    # 应显示两个 healthy

# 5. 验证
uv run pytest -v
```

### 常用命令

```bash
uv run pytest -v                           # 全部测试
uv run pytest tests/path/test_x.py::test_y # 单个测试
uv run ruff check . && uv run ruff format .  # lint + 格式化
uv run mypy backend                        # 类型检查
docker compose up -d db redis              # 启动依赖服务
docker compose down                        # 停止（保留数据）
```

---

## 项目结构

```
NetSentinel/
├── backend/
│   ├── core/           # 配置 · 日志 · 数据库 · 异常 · 事件总线
│   ├── models/         # SQLAlchemy ORM
│   ├── schemas/        # Pydantic 出入参
│   ├── repositories/   # 数据访问层
│   ├── services/       # 领域逻辑
│   ├── detection/      # feeders · parsers · 告警管道 · ML
│   ├── agents/         # LangGraph 图 · 节点 · prompts · tools
│   ├── api/            # 路由 + WebSocket
│   ├── middleware/     # 限流 · 请求日志 · 异常处理
│   └── workers/        # 重放 · 评测 · 日报
├── tests/              # pytest（镜像 backend 结构）
├── frontend/           # React + TypeScript + Vite
├── docs/plans/         # 设计文档与实施计划
└── docker-compose.yml  # 本地依赖服务
```

---

## 文档

| 文档 | 说明 |
|---|---|
| [`docs/plans/2026-09-24-NetSentinel-design.md`](docs/plans/2026-09-24-NetSentinel-design.md) | 完整设计文档：架构、数据流、研判层、评测方案 |
| [`docs/plans/2026-09-24-NetSentinel-phase1-implementation.md`](docs/plans/2026-09-24-NetSentinel-phase1-implementation.md) | 期 1 实施计划（TDD 逐任务） |
| [`AGENTS.md`](AGENTS.md) | 项目约定与协作规范 |

---

## 进度

### 期 1：基础闭环

- [x] 项目脚手架与配置
- [x] 结构化日志与异常体系
- [x] PostgreSQL + Redis 本地服务
- [ ] 数据库模型与迁移
- [ ] 告警 Schema / 数据访问层 / 领域服务
- [ ] CICIDS2017 数据准备 + ML 训练与推理
- [ ] 准实时重放 Feeder
- [ ] DeepSeek 客户端 + LangGraph 分诊图
- [ ] API + WebSocket 实时推送
- [ ] 前端（Dashboard / 告警流 / 流控）
- [ ] 一键启动 + CI + 端到端验收

### 期 2：规则引擎 + 深度调查

- [ ] Suricata 集成与 EVE 解析
- [ ] 去重 / 抑制规则 / GeoIP 富化
- [ ] 条件边路由 + Investigation Agent + 工具集
- [ ] 证据链持久化 + Human-in-the-loop

### 期 3：评测与打磨

- [ ] 多模型对比实验
- [ ] LLM 研判评测（一致率 / 耗时 / 成本）
- [ ] 安全日报
- [ ] 演示脚本与报告素材

---

## 设计取舍

几个**明确不做**的事，以及原因：

- **不做真实网卡实时抓包** —— 架构预留接口，但研究的重点在检测与研判质量；用数据集重放即可复现实时观感
- **不做 IPS 串联阻断** —— 阻断的风险与验证成本远超本项目范围
- **不做特征级融合** —— 两引擎在告警层统一即可，特征级融合是另一个课题
- **不用 Kafka / K8s / 微服务** —— 单人项目，复杂度换来的是维护负担而非能力

### 为什么是 FastAPI 而不是 Spring Boot

本项目的核心是机器学习检测与 LLM 研判，两者生态均以 Python 为主。采用 Python 全栈可让**检测、ML、Agent、数据处理用同一语言链路**，避免跨语言微服务带来的部署与运维复杂度。性能瓶颈在 LLM 调用与 IO 等待，而非需要 JVM 支撑的高并发计算。

---

## 致谢与借鉴

本项目在设计与实现中借鉴了以下开源工作，谨致谢意：

| 项目 | License | 借鉴内容 |
|---|---|---|
| [IntruShield NIDS](https://github.com/harisx404/intrushield-nids) | MIT | 分层架构骨架、EVE tail 管道、事件总线、WebSocket 管理 |
| [alert-triage-copilot](https://github.com/KMKolos/alert-triage-copilot) | MIT | 结构化研判输出、evidence trail、工具契约设计 |
| [Suricata](https://github.com/OISF/suricata) | GPL-2.0 | 规则引擎（作为独立工具调用，非代码引用）|

> **知识产权说明**：所有借鉴点均重写实现并在此明确标注来源。本项目自身以 **MIT** 协议开源。

---

## License

[MIT](LICENSE) © 2026 Zhou Huang
