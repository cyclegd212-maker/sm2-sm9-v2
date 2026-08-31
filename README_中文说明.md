# sm2-sm9-v2 仓库说明

本仓库用于保存论文《SM2_SM9_V2 投稿标准化研究稿（证明细化与新颖性审计版）》配套的参考实现与实验脚本。

## 目录说明

- `src/v2_scheme.py`：V2 方案参考实现
- `bench/benchmark.py`：基准测试主程序
- `bench/collect_env.py`：环境记录脚本
- `tests/`：静态检查脚本
- `data/raw/timings.csv`：原始计时数据（当前仅表头，未实测）
- `data/processed/summary.csv`：汇总统计数据（当前仅表头，未实测）
- `metadata/experiment_manifest.json`：实验状态与依赖说明
- `paper/`：论文 PDF 与 LaTeX 源文件
- `docs/`：补充说明与 AI 标准化提示词

## 当前状态

当前版本严格遵守：**没有真实实测，就不填写任何毫秒/纳秒结论值**。

因此：
- `experiment_manifest.json` 中状态为 `NOT_MEASURED`
- `data/raw/timings.csv` 与 `data/processed/summary.csv` 暂不含真实测试结果

## 仓库状态

规范仓库地址：`https://github.com/cyclegd212-maker/sm2-sm9-v2`。

本仓库按“证据可追溯”原则维护：论文源文件、实验代码、依赖版本、原始 CSV、汇总 CSV 与运行日志应与具体 Git commit 对应。当前尚未执行正式性能测试，因此不得从本仓库推导或引用任何毫秒级性能结论。

## 后续实验要求

在正式投稿前，建议补齐以下内容：
1. 运行 `pytest` 完成正确性检查；
2. 运行 `scripts/run_all.sh` 或 `scripts/run_all.ps1` 生成原始日志；
3. 保存 `environment.json`、`timings.csv`、`summary.csv` 与运行日志；
4. 在论文中再填写真实性能数据。
