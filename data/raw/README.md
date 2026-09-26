# 原始数据说明

本目录存放检测与演示所用的 pcap 样本，**数据本体不入库**（已在 .gitignore 中排除）。

## 当前需要的数据

检测层用 Suricata 离线读取 pcap 产出告警，所以需要**带攻击流量的 pcap**。

**首选**：CICIDS2017 的 pcap 版本（与联合国 UNB 官方一致，含真实攻击）
- 官方 pcap 分日的压缩包体积很大（单日数 GB），
  **建议只取其中的攻击时段**，或使用社区切好的小样本。

**备选来源**：
| 来源 | 说明 |
|---|---|
| `hf-mirror.com` 上的 CICIDS2017 数据集 | 部分仓库提供 pcap（非仅 CSV）|
| Kaggle 上的 CICIDS2017 pcap 切分 | 需账号 |
| malware-traffic-analysis.net | 单条恶意流量样本，体积小，适合演示 |
| 自行用 tcpdump/scapy 构造 | 完全可控，适合演示特定规则 |

## 下载注意事项

- **HuggingFace 官方域名被墙**，使用镜像 **`hf-mirror.com`**（实测 20+ MB/s）。
- 官方 UNB 服务器国内不可达，不要尝试直连。
- 磁盘空间有限时优先选**小样本**，演示不需要完整数据集。

## 使用方式

```bash
# 用 Suricata 离线跑 pcap（在 Docker 中执行）
suricata -r data/raw/<某个>.pcap -l data/logs

# 或通过系统接口触发重放（Feed Control 页面 / POST /api/v1/feeds/replay）
```

## 关于曾经用过的 CICIDS2017 特征 CSV

项目早期曾计划"规则 + ML 双引擎"，因此下载过 CICIDS2017 的
`MachineLearningCSV`（78 维流特征 + 标签，约 316MB）。
**该方案已整体移除**（原因见设计文档 §15.5），这些 CSV 不再需要。

若将来重新评估 ML 检测，数据集信息如下（供参考）：

| 文件 | 行数 | 攻击样本 |
|---|---|---|
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 225,745 | DDoS 128,027 |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 286,467 | PortScan 158,930 |
| `Monday-WorkingHours.pcap_ISCX.csv` | 529,918 | —（纯正常流量）|

来源：`hf-mirror.com` 的 `c01dsnap/CIC-IDS2017`。
注意其列名带前导空格（如 `" Destination Port"`），读取后需 strip。
