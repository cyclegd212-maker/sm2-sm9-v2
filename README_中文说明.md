# sm2-sm9-v2 仓库说明

本仓库用于维护 SM2/PKI 发送者到增强 SM9 接收者的 V2 异构在线/离线签密研究代码、证明审计材料与可复现实验骨架。

## 目录说明

- `src/v2_scheme.py`：V2 方案参考实现
- `bench/benchmark.py`：基准测试主程序
- `bench/collect_env.py`：环境记录脚本
- `tests/`：静态/源码契约测试
- `data/raw/timings.csv`：原始计时数据（当前仅表头，未实测）
- `data/processed/summary.csv`：汇总统计数据（当前仅表头，未实测）
- `metadata/experiment_manifest.json`：实验状态与依赖说明
- `docs/`：补充说明与投稿标准化 AI 提示词
- `paper/STATUS.md`：论文版本、文件名和 SHA-256 完整性记录；PDF/TeX 交付件当前单独生成，不虚构为已经存放在仓库中的文件

## 当前状态

当前版本严格遵守：**没有真实实测，就不填写任何毫秒/纳秒结论值**。

因此：
- `experiment_manifest.json` 中状态为 `NOT_MEASURED`；
- `data/raw/timings.csv` 与 `data/processed/summary.csv` 暂不含真实测试结果；
- 当前 Python 依赖仅作为方程/协议参考基线，不能据此直接声称 GB/T SM9 参数兼容或正式性能水平。

## 仓库状态

规范仓库：`cyclegd212-maker/sm2-sm9-v2`。

本仓库按“证据可追溯”原则维护：实验代码、依赖 commit、原始 CSV、汇总 CSV、环境记录和运行日志均应与具体 Git commit 对应。论文 PDF/TeX 在正式上传或发布前，用 `paper/STATUS.md` 记录文件名与 SHA-256，避免把未实际存在的附件写成已入库。

## 当前需要重点审查的理论问题

V2 的 Type-II 恶意 KGC 机密性使用缩放 CDH 嵌入；Type-I 采用非标准的 Known-Secret Replacement（Type-I-KSR）模型。后者相较经典 certificateless Type-I 公钥替换模型更受限，是正式投稿前最需要继续论证模型合理性和新颖性的部分。

## 后续实验要求

正式投稿前应：
1. 通过权威 SM2、SM3、SM9 测试向量；
2. 固定正式实现库及 commit、编译参数、CPU/系统/电源模式；
3. 运行 `pytest` 和完整协议正确性测试；
4. 运行 `scripts/run_all.sh` 或 `scripts/run_all.ps1` 生成原始记录；
5. 保存 `environment.json`、`timings.csv`、`summary.csv` 与日志；
6. 最后再把真实性能结果写入论文。
