# 期 1 验收清单

> 用途：本地跑一遍，确认期 1 的核心链路真的可用。
> 出现任何一步与预期不符，记录下来告诉我。

---

## 0. 前置检查

```bash
cd /Users/hazer/code/NetSentinel

# Docker 容器应显示两个 healthy
docker compose ps

# 确认 .env 存在且含 key（只看长度，别打印内容）
uv run python -c "from backend.core.config import settings; print('key 长度:', len(settings.DEEPSEEK_API_KEY))"
# 预期：key 长度: 35
```

---

## 1. 自动化测试（最快的一关）

```bash
# 后端：137 个测试
uv run pytest -q
# 预期：137 passed

# 后端代码质量
uv run ruff check .        # 预期：All checks passed!
uv run mypy backend        # 预期：Success: no issues found

# 前端：6 个测试 + 构建
cd frontend
npm run test               # 预期：6 passed
npm run build              # 预期：built in ~1s
cd ..
```

---

## 2. 起服务

**终端 A**（后端）：

```bash
./scripts/dev.sh
```

预期输出末尾：

```
==> 4/4 启动后端 API（http://localhost:8000/docs）
INFO:     Uvicorn running on http://127.0.0.1:8000
```

**终端 B**（前端）：

```bash
cd frontend && npm run dev
```

预期：`Local: http://localhost:5173/`

---

## 3. 验收检查点

### ✅ 检查点 1：接口可用

浏览器打开 http://localhost:8000/docs

预期：Swagger 页面，能看到 7 个路径（alerts / feeds / statistics / health）

### ✅ 检查点 2：前端能打开

浏览器打开 http://localhost:5173

预期：
- 左上角显示 `NetSentinel`
- 导航栏右侧有状态标签：**"实时已连接"**（绿色点）
- 仪表盘显示 4 个指标卡（当前都是 0）

> 若显示"实时未连接"，说明 WebSocket 没连上 —— 检查后端是否在跑。

### ✅ 检查点 3：启动重放，告警流式出现

1. 点左侧 **「数据重放」**
2. 文件下拉应自动选中 `data/logs/demo-eve.json`
3. 倍速填 `5`（慢一点，能看清效果）
4. 点 **「开始重放」**，看到绿色提示
5. **立刻切到「实时告警」页**

预期：
- 告警**一条条**冒出来（不是一次全出）
- 每条有时间、严重度标签（颜色不同）、签名、源 IP
- 大约 28 条（原始 40 条，去重掉 12 条）
- 时间列是递增的

> **这是"准实时"的核心效果** —— 倍速 5 意味着大约 10-20 秒播完。

### ✅ 检查点 4：AI 研判

1. 在告警列表点**任意一条签名的链接**进入详情
2. 页面上半部分是告警信息（五元组、分类、引擎）
3. 下半部分标题是 **「AI 研判」**

预期：
- 首次进入可能显示"尚无研判结果"，等几秒会自动刷新
- 出现研判卡片，包含：
  - 结论标签（**真实攻击** / **误报** / **待人工复核** 三色之一）
  - 置信度进度条
  - 中文 summary（2-3 句）
  - 可能的"攻击类型"、"MITRE ATT&CK"标签
  - 处置建议列表
  - 底部显示模型名、耗时、token 数

> **注意**：目前只有 Suricata 一条规则告警，模型拿到的信息较少，
> 多数会判为「待人工复核」且置信度偏低 —— **这是设计的诚实行为，
> 不是 bug**。期 2 的深度调查会补充更多证据。

### ✅ 检查点 5：仪表盘有数据

回到 **「仪表盘」** 页

预期：
- 「告警总数」等于检查点 3 里看到的条数
- 「已研判」大于 0（看过的告警）
- 两个饼图有内容：**告警严重度分布**、**AI 研判结论分布**

### ✅ 检查点 6：数据库真的是数据源

```bash
# 直接查数据库（绕开 API），确认数据落库了
docker compose exec -T db psql -U netsentinel -d netsentinel -c \
  "SELECT severity, count(*) FROM alerts GROUP BY severity ORDER BY 2 DESC;"

docker compose exec -T db psql -U netsentinel -d netsentinel -c \
  "SELECT verdict, confidence, left(summary, 40) FROM triage_results LIMIT 5;"
```

预期：能看到与页面一致的数据。

### ✅ 检查点 7：WebSocket 断线重连

1. 在 **「实时告警」** 页保持打开
2. 到终端 A，按 `Ctrl-C` 停掉后端
3. 观察前端 —— 状态标签变灰**"实时未连接"**
4. 重新 `./scripts/dev.sh` 起后端
5. 期望：**几秒内自动**变回绿色**"实时已连接"**（无需刷新页面）

> 这验证了前端 WebSocket 的指数退避重连。

---

## 4. 反向验证（可选，但很有说服力）

### 去重确实生效

```bash
# 演示数据里刻意构造了 12 条重复（同源同签名）
grep -c '"event_type":"alert"' data/logs/demo-eve.json     # 40
# 重放后库里应该是 28（40 - 12）
```

### 检测层不依赖 LLM

临时把 `.env` 里的 key 清空，重启后端，再跑一次重放：
- ✅ 告警仍然正常出现（检测层独立工作）
- ⚠️ AI 研判卡片显示"自动研判未完成"（降级提示，**告警没丢**）

**这验证了"LLM 失败降级而非丢弃"的设计** —— 研判器故障不该导致漏报。

---

## 5. 清空重来

```bash
# 清空数据，重新验收
docker compose exec -T db psql -U netsentinel -d netsentinel -c "TRUNCATE alerts CASCADE;"

# 重新生成演示数据（可选，换个随机种子会不同）
uv run python scripts/generate_demo_eve.py --count 60 --out data/logs/demo-eve.json
```

---

## 6. 检查结果记录

| 检查点 | 结果 | 备注 |
|---|---|---|
| 1 接口可用 | ⬜ | |
| 2 前端能打开 / WS 已连接 | ⬜ | |
| 3 重放：告警流式出现 | ⬜ | |
| 4 AI 研判卡片 | ⬜ | |
| 5 仪表盘有数据 | ⬜ | |
| 6 数据库直查一致 | ⬜ | |
| 7 断线自动重连 | ⬜ | |

---

## 常见问题

| 现象 | 原因 / 处理 |
|---|---|
| 前端"实时未连接" | 后端没起；或 8000 端口被占 |
| 测试报 `role "netsentinel" does not exist` | 本机有别的 PG 抢了 5432（历史问题，已处理） |
| 重放点了没反应 | 看终端 A 日志；确认 `data/logs/demo-eve.json` 存在 |
| AI 研判一直是空 | `.env` 里 key 没配 / 无效；看后端日志有无 LLM 报错 |
| 告警一次全出来 | 倍速设太大了（如 10000），改成 5 观察 |
