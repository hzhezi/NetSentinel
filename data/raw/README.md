# 原始数据说明

本目录存放下载的公开数据集，**不入库**（已在 .gitignore 中排除 `data/`）。

## 当前数据

CICIDS2017 的官方特征 CSV（即官方 `MachineLearningCSV` 内容），
来源为 HuggingFace 镜像 `c01dsnap/CIC-IDS2017`：

| 文件 | 行数 | 攻击样本 | 正常样本 |
|---|---|---|---|
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 225,745 | DDoS 128,027 | 97,718 |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 286,467 | PortScan 158,930 | 127,537 |
| `Monday-WorkingHours.pcap_ISCX.csv` | 529,918 | — | 529,918 |

合计约 104 万条 flow，含 28.7 万条攻击样本。

## 为什么用镜像

- 官方源（美国 UNB 服务器）国内不可达
- HuggingFace 官方域名 `huggingface.co` 被墙
- **`hf-mirror.com` 可用**，实测下载速度 20+ MB/s

## 重新下载

```bash
mkdir -p data/raw && cd data/raw
DS="c01dsnap/CIC-IDS2017"
for f in \
  "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv" \
  "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv" \
  "Monday-WorkingHours.pcap_ISCX.csv"
do
  curl -L --fail -O "https://hf-mirror.com/datasets/$DS/resolve/main/$f"
done
```

## 数据格式要点

- **79 列** = 78 个流特征 + `Label`
- **列名带前导空格**（如 `" Destination Port"`）—— 这是官方数据的已知问题，
  读取后必须 `df.columns = [c.strip() for c in df.columns]`
- 存在 `inf` / `NaN`（除零产生的），训练前需清洗
- 其他可用的量表来源见设计文档 §4.1

## 可选的额外数据（后续需要时）

HF 上还有 `yasirchemmakh/Cicids2017_Suricata_Logs` ——
**别人用 Suricata 跑 CICIDS2017 得到的 eve 日志**。
期 2 的规则引擎通道可以参考/对比，但不是必需（那时我们会自己跑 Suricata）。
