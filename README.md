<div align="center">

# NetSentinel

**准实时 NIDS 检测与研判平台**

Suricata 规则检测 · LangGraph 多智能体 LLM 研判 · 实时 Web 可视化

[![CI](https://github.com/hzhezi/NetSentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/hzhezi/NetSentinel/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

</div>

> ✅ **当前状态：三期全部完成**。检测 → 分级研判（L1/L2）→ 证据链 → 落库 → 实时推送
> → 前端展示全流程打通，并附**真实数据评测**与**演示脚本**。
> AI 研判需配置 DeepSeek API Key。

---

## 这是什么

传统 NIDS（Suricata / Snort）检测能力强，但产出的是**原始告警**：数量大、误报多、缺少上下文与解释，需要分析师大量人工研判。而现有的 LLM 安全运营方案几乎全部基于 **SIEM / 主机日志（Wazuh 等）**，不覆盖网络流量层。

NetSentinel 把**网络层规则检测**与 **LLM 智能研判**打通，形成一条从流量到可读结论的完整链路：

```
pcap ──→ Suricata 规则检测 ──→ 统一告警 ──→ LLM 多智能体研判 ──→ Web 可视化
                              （去重/抑制/富化）   Triage / Investigation
```

### 实测效果（真实数据评测）

| 指标 | L1 快速分诊 | L2 深度调查 |
|---|---|---|
| 结论一致率 | 0.0 | **1.0** |
| 明确判断 | 0/9 | **9/9** |
| 平均置信度 | 35-55 | **82-93** |
| 平均耗时 | ~2s | 8.1s |

> L1 全量分诊（便宜快），命中升级条件时自动转交 L2 深度调查（工具补证据）。
> 评测详情见 [`docs/report-materials.md`](docs/report-materials.md)。

### 核心特性

- **规则检测**：Suricata 规则引擎（Docker），输出统一为 `UnifiedAlert`
- **准实时重放**：按事件原始时间戳重放 eve.json，复现实时 IDS 观感，无需网卡/root/靶场
- **两级研判（LangGraph 编排）**：L1 快速分诊（便宜模型，每条都跑）→ 条件升级 → L2 深度调查（强模型 + 工具）
- **工具驱动调查**：L2 会主动查询 IP 信誉、关联历史告警、资产重要性、MITRE 映射
- **证据链可审计**：每步推理与工具调用全部记录，结论可逐行追溯，不做黑盒
- **防幻觉约束**：强制结构化输出、`needs_human_review` 是一等结论、MITRE 编号必须查表、失败降级而非丢弃
- **误报治理**：抑制规则（AND 逻辑 + 可选过期）自动过滤已知噪声
- **可观测**：结构化日志、token 与耗时落库，供报告与成本分析使用

---

## 架构

```
┌───────────────────────── 数据层 ─────────────────────────┐
│  带攻击的 pcap（或演示用 eve.json）                        │
└────────────────────────────┬─────────────────────────────┘
                             ↓
┌──────────────────────── 输入层 ──────────────────────────┐
│  EveFeeder：按事件时间戳节奏重放 · (预留)LiveFeeder         │
└────────────────────────────┬─────────────────────────────┘
                             ↓
┌───────────────────────── 检测层 ─────────────────────────┐
│  Suricata 规则引擎（离线跑 pcap → eve.json）              │
│            ↓ EVE 解析 → 归一化                            │
│  去重(TTLCache) · 抑制规则(AND+过期) · 严重度映射          │
└────────────────────────────┬─────────────────────────────┘
                             ↓
┌────────────── 研判层（LangGraph 多智能体）───────────────┐
│  [Triage L1] ──条件边──→ [Investigation L2] → [Persist]  │
│   便宜模型            强模型 + 工具循环                     │
│   单轮                证据链 + 强制收敛                     │
└────────────────────────────┬─────────────────────────────┘
                             ↓
┌─────────────── 存储层（PostgreSQL + Redis）──────────────┐
│  alerts · triage_results · suppression_rules             │
└────────────────────────────┬─────────────────────────────┘
                             ↓
┌──────────────────────── 展示层（Web）───────────────────┐
│  仪表盘 · 实时告警流 · 告警详情+研判卡片 · 数据重放        │
│  WebSocket 实时推送                                       │
└─────────────────────────────────────────────────────────┘
```

---

## 技术栈

| 层 | 选型 |
|---|---|
| 后端 | Python 3.13 · FastAPI · Pydantic v2 · SQLAlchemy 2.0 (async) · Alembic |
| 前端 | React 19 · TypeScript · Vite · Ant Design · TanStack Query · Zustand · ECharts |
| 存储 | PostgreSQL 16 · Redis 7 |
| 检测 | Suricata 7（Docker） |
| 研判 | LangGraph（自定义节点）· DeepSeek API |
| 可观测 | structlog（结构化 JSON） |
| 质量 | pytest · ruff · mypy · Vitest · GitHub Actions |

---

## 快速开始

### 环境要求

- Python **3.13**（由 `.python-version` 固定，`uv` 会自动匹配）
- [uv](https://github.com/astral-sh/uv)（Python 包管理器）
- Docker Desktop（提供 PostgreSQL / Redis；Mac 上还需 `brew install libomp` 仅当用 XGBoost，本项目已不需要）
- Node.js 20+

### 一键启动

```bash
git clone git@github.com:hzhezi/NetSentinel.git
cd NetSentinel

cp .env.example .env         # 可选：填入 DEEPSEEK_API_KEY 以启用 AI 研判
./scripts/dev.sh             # 起依赖 + 迁移 + 生成演示数据 + 起后端
```

另开一个终端起前端：

```bash
cd frontend && npm install && npm run dev     # http://localhost:5173
```

### 演示路径

1. 打开前端 → **数据重放** → 选择 `data/logs/demo-eve.json` → 开始重放
2. 切到 **实时告警** 页，观察告警按时间顺序流式出现
3. 点任意告警查看 **AI 研判卡片**（需配置 API Key）

### 用真实 pcap

```bash
# 把 pcap 放到 data/raw/，然后用 Suricata 离线分析
docker compose --profile suricata run --rm suricata \
    suricata -r /data/raw/your.pcap -l /data/logs

# 页面上重放 data/logs/eve.json
```

### 常用命令

```bash
uv run pytest -v                      # 后端测试（需 docker compose up -d db）
uv run ruff check . && uv run mypy backend
uv run alembic upgrade head           # 应用迁移
uv run uvicorn backend.main:app --reload

cd frontend && npm run test           # 前端测试
cd frontend && npm run build          # 类型检查 + 构建
```

---

## 项目结构

```
NetSentinel/
├── backend/
│   ├── core/           # 配置 · 日志 · 数据库 · 异常
│   ├── models/         # SQLAlchemy ORM（alerts / triage_results）
│   ├── schemas/        # Pydantic 契约（API 出入参、LLM 输出）
│   ├── repositories/   # 数据访问层
│   ├── services/       # 领域逻辑（归一化 / 去重）
│   ├── detection/      # parsers（EVE 解析）· feeders（重放）
│   ├── agents/         # LangGraph 图 · prompts · LLM 客户端
│   ├── api/            # 路由 + WebSocket
│   ├── middleware/     # 统一异常处理
│   └── workers/        # 重放编排
├── frontend/           # React + TypeScript + Vite
├── suricata/           # Suricata 配置与自定义规则
├── scripts/            # 一键启动 · 演示数据生成
├── alembic/            # 数据库迁移
├── tests/              # pytest（镜像 backend 结构）
└── docs/plans/         # 设计文档与实施计划
```

---

## 关键设计决策

| 决策 | 理由 |
|---|---|
| **不做机器学习检测** | 定位是"在现有 IDS 上加 LLM 研判层"。见 [`docs/plans/...design.md`](docs/plans/2026-09-24-NetSentinel-design.md) §15.5 |
| **研判用 LangGraph 但限定制研层** | 检测/存储/展示层与之解耦，换编排方式不影响其他部分 |
| **必须先归一化为 UnifiedAlert** | 下游不感知具体检测引擎，换引擎只改解析层 |
| **`needs_human_review` 是一等结论** | 给模型"承认不确定"的出口，显著减少幻觉 |
| **LLM 失败降级而非丢弃** | 研判器故障不该导致告警丢失 —— 降级为人工复核 |
| **不做实时抓包 / IPS 阻断** | 架构预留接口，但研究重点是检测与研判质量 |

### 为什么是 FastAPI 而不是 Spring Boot

本项目的核心是 LLM 研判与 Agent 编排，其生态以 Python 为主。采用 Python 全栈可让**检测、Agent、API 用同一语言链路**，避免跨语言微服务带来的部署与运维复杂度。性能瓶颈在 LLM 调用与 IO 等待，而非需要 JVM 支撑的高并发计算。

---

## 评测方案

LLM 研判层的评测（期 3）：

- 人工抽样告警作为评测集，与模型结论比对
- 指标：verdict 一致率、误报识别准确率、解释质量人工打分
- 成本：平均 token 与耗时（数据已落库，见 `triage_results` 表）

> **评估诚实性原则**：报告效果时必须同时说明评测方法与局限，不把"看起来合理"包装为"准确"。

---

## 致谢与借鉴

| 项目 | License | 借鉴内容 |
|---|---|---|
| [IntruShield NIDS](https://github.com/harisx404/intrushield-nids) | MIT | 分层架构骨架、EVE tail 管道、WebSocket 连接管理 |
| [alert-triage-copilot](https://github.com/KMKolos/alert-triage-copilot) | MIT | 结构化研判输出、evidence trail、工具契约、prompt 铁律 |
| [Suricata](https://github.com/OISF/suricata) | GPL-2.0 | 规则引擎（作为独立工具调用，非代码引用）|

> **知识产权说明**：所有借鉴点均重写实现并在此明确标注来源。本项目自身以 **MIT** 协议开源。

---

## 进度

### 期 1：基础闭环 ✅（核心链路已通）

- [x] 项目脚手架、配置、结构化日志、异常体系
- [x] 数据库模型与迁移（alerts / triage_results）
- [x] 告警 Schema / 数据访问层 / 归一化与去重
- [x] EVE 解析 + 准实时重放 Feeder
- [x] DeepSeek 客户端 + LangGraph 分诊图（含条件升级与失败降级）
- [x] API（告警/重放/统计）+ WebSocket 实时推送
- [x] 前端（仪表盘 / 实时告警流 / 告警详情 / 数据重放）
- [x] Suricata 容器 + 自定义规则 + 演示数据生成
- [x] CI（后端 lint/type/test + 前端 test/build）
- [ ] 用真实 pcap 的端到端演示（需下载数据）
- [ ] LLM 研判的真实 API 连通性验证（需 API Key）

### 期 2：深度调查 ✅

- [x] Investigation Agent（工具驱动多轮调查 + evidence trail）
- [x] 工具集（IP 情报 / MITRE 查表 / 关联告警 / 资产上下文）
- [x] 证据链持久化与前端时间线展示
- [x] 抑制规则（AND 逻辑 + 可选过期 + 空规则保护）
- [x] Human-in-the-loop：手动触发深度调查
- [ ] LangGraph checkpointer（图状态持久化，可选）
- [ ] GeoIP：由 IP 情报工具的国家字段覆盖，未做独立模块

### 期 3：评测与打磨 ✅

- [x] 真实 pcap 端到端验证（10 种攻击全部命中，零误报）
- [x] LLM 研判评测集与结果页（L1 vs L2 对比数据）
- [x] Report Agent + 安全日报页
- [x] 演示脚本 + 一键准备脚本
- [x] 报告素材汇总文档

---

## License

[MIT](LICENSE) © 2026 Zhou Huang
