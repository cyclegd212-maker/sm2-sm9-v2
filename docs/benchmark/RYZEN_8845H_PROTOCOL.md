# Ryzen 7 8845H 最终投稿实测协议

本协议用于生成论文**最终投稿性能表**。GitHub Actions 的 AMD EPYC 数据只能作为 CI 可复现性证据，不能替代本协议。

## 1. 目标平台

预期机器：

- 设备：Lenovo XiaoXinPro 16 AHP9；
- CPU：AMD Ryzen 7 8845H；
- 内存：32 GB；
- 操作系统：Windows 64-bit。

上述信息在正式实验时必须由脚本/系统实际采集并确认；未采集字段不得凭记忆预填。

## 2. 固定源码身份

正式运行前：

1. `git status --porcelain=v1` 必须为空；
2. 记录 V2 `git rev-parse HEAD`；
3. GmSSL 固定到 `24ae482701a7b124826c382fffc55c19f76d475d`；
4. GmSSL 和 V2 均使用 Release 构建；
5. 不得在四种消息长度之间修改源码、编译 flags 或电源配置。

一组 benchmark 只能包含一个 V2 commit 和一个 GmSSL commit。

## 3. 系统准备

建议在 Windows Developer PowerShell 中运行，并确保可用：

- Git；
- CMake；
- Ninja（默认脚本使用 Ninja，可通过参数改 generator）；
- 支持 C11 的 MSVC/clang-cl/GCC 工具链；
- Python 3。

在实验前：

- 插电；
- 关闭 Windows Update/大型下载/杀毒全盘扫描等明显后台负载；
- 选择固定电源模式并记录；
- 不在实验中途切换电源计划；
- 尽量保持室温/散热条件稳定；
- 不人为挑选“最好的一次”。

CPU affinity 不是强制条件。若使用 affinity，则必须记录实际绑定策略，并在全部实验中保持一致；若不用，也要明确记录未固定 affinity。

## 4. 一键运行

仓库根目录执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\native\scripts\run_submission_windows.ps1
```

默认参数：

- warmup = 1000；
- iterations = 10000 / 每个 message-size × phase；
- message sizes = 20, 128, 1024, 4096 B；
- build type = Release；
- pinned GmSSL commit = `24ae482701a7b124826c382fffc55c19f76d475d`。

脚本会 fail closed：GmSSL 上游测试、native V2 测试、任何 benchmark 或 evidence validation 失败时，整组实验失败，不允许继续把部分结果写进论文。

## 5. 必须通过的测试

正式计时前必须通过：

- GmSSL `sm2_sign`；
- GmSSL `sm3`；
- GmSSL `sm3_hmac`；
- GmSSL `sm9`；
- V2 round-trip tests；
- V2 tamper/错误密钥/非法点测试；
- token reuse rejection；
- Type-I-KSR / Type-II knowledge-path tests。

测试失败意味着这次性能数据无效。

## 6. 计时阶段

每个消息长度测量：

- `receiver_keygen`；
- `offline_signcrypt`；
- `online_signcrypt`；
- `sender_total`；
- `unsigncrypt`；
- `sm2_fixed_base_mul`；
- `sm9_g1_mul`；
- `sm9_pairing`；
- `sm9_gt_exp`。

warmup 不进入 raw CSV。正式样本逐次记录纳秒值，不只保留均值或最好一次。

## 7. 统计规则

`summary.csv` 必须完全由 `raw.csv` 自动重建，包含：

- n；
- arithmetic mean；
- median；
- sample standard deviation；
- nearest-rank P95。

禁止手工修改 summary。`validate_evidence.py` 会检查：

- 四种消息长度都存在；
- 九个 phase 都存在；
- 每组恰好 10000 次迭代；
- run/commit identity 单一；
- `summary.csv` 与 fresh recomputation 逐字节一致。

## 8. 输出证据目录

成功运行后生成：

`artifacts/submission-ryzen8845h-<UTC timestamp>/`

至少包含：

- `environment.json`；
- `raw.csv`；
- `summary.csv`；
- `hashes.json`；
- GmSSL clone/checkout/configure/build/install logs；
- `upstream-tests.log`；
- native configure/build/test logs；
- `benchmark.log`；
- `evidence-validation.log`。

这一完整目录才是论文性能数字的证据源。

## 9. 论文允许使用数据的条件

只有满足以下全部条件，才能从 `summary.csv` 生成论文表格/图片：

1. `evidence-validation.log` 为 PASS；
2. working tree 在实验起点干净；
3. V2/GmSSL commit 与 environment/hashes/raw 一致；
4. 每组样本数正确；
5. 所有 correctness/security tests 通过；
6. summary 可从 raw 精确重算；
7. 没有把 GitHub Actions EPYC 数据与 Ryzen 数据混在同一“平台实测”表中。

正式论文建议同时归档 evidence 目录 SHA-256 或发布为 GitHub release / Zenodo supplement，以便审稿人复核。
