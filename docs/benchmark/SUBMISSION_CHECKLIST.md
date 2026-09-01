# 投稿实测检查清单

## A. 源码身份

- [ ] V2 working tree clean
- [ ] V2 commit 已记录
- [ ] GmSSL commit = `24ae482701a7b124826c382fffc55c19f76d475d`
- [ ] GmSSL working tree clean / detached at pinned commit
- [ ] Release 构建
- [ ] 编译器/CMake 版本已记录

## B. 平台信息

- [ ] 设备型号由系统/人工核对：Lenovo XiaoXinPro 16 AHP9
- [ ] CPU 由系统实际读取：AMD Ryzen 7 8845H
- [ ] Windows edition/build 已记录
- [ ] BIOS 版本已记录（若自动脚本未采集，则补充到实验说明，不改 raw CSV）
- [ ] 电源模式已记录并在整个实验期间保持不变
- [ ] CPU affinity 策略已记录（固定或未固定均可，但不能不说明）
- [ ] 插电、避免明显后台负载

## C. 正确性与安全测试

- [ ] GmSSL SM2 sign test PASS
- [ ] GmSSL SM3 test PASS
- [ ] GmSSL HMAC-SM3 test PASS
- [ ] GmSSL SM9 test PASS
- [ ] Native V2 round-trip PASS
- [ ] 0/1/20/128/1024/4096 B round-trip PASS
- [ ] X_B tamper reject
- [ ] U tamper reject
- [ ] C tamper reject
- [ ] SM2 r/s tamper reject
- [ ] HMAC tag tamper reject
- [ ] wrong x_B reject
- [ ] wrong d_B reject
- [ ] illegal/infinity point reject
- [ ] token reuse reject

## D. 正式计时

- [ ] Warmup >= 1000
- [ ] Iterations >= 10000 / size × phase
- [ ] Message sizes = 20, 128, 1024, 4096 B
- [ ] Nine phases all measured
- [ ] Warmup rows not written to raw CSV
- [ ] No zero/placeholder timing rows
- [ ] Four sizes share one run ID, one V2 SHA, one GmSSL SHA

## E. 证据完整性

- [ ] `environment.json`
- [ ] `raw.csv`
- [ ] `summary.csv`
- [ ] `hashes.json`
- [ ] build logs
- [ ] upstream tests log
- [ ] native tests log
- [ ] benchmark log
- [ ] `evidence-validation.log` says PASS
- [ ] summary fresh recomputation exactly matches archived summary
- [ ] raw/summary SHA-256 已保存

## F. 论文回写

只有 A-E 全部满足后：

- [ ] `submission_benchmark.status` 改为 `MEASURED`
- [ ] 性能表从 `summary.csv` 自动生成/抄录并二次核对
- [ ] 图表从 archived CSV 生成
- [ ] 正文给出 V2 commit、GmSSL commit、平台和统计规则
- [ ] CI EPYC benchmark 明确标记为 reproducibility evidence，不与 Ryzen submission benchmark 混用
- [ ] 不声称“所有指标最优”
- [ ] 若某对比方案使用不同实现/曲线/硬件，不直接做毫秒差值排名

## G. 安全证明投稿前门禁

性能实验完成并不自动意味着可以投稿。还必须：

- [ ] Type-I 在全文统一限定为 Known-Secret Replacement
- [ ] 明确 KSR 弱于经典任意 Type-I ReplacePublicKey
- [ ] Type-II CDH 缩放嵌入的 H1/KDF oracle 表完整
- [ ] 挑战身份猜测、c=0、关键 KDF query 猜测损失完整
- [ ] HMAC multi-key advantage/会话猜测损失明确
- [ ] 同消息替代随机化 SM2 签名不错误归入普通 EUF-CMA
- [ ] SM3-KDF ROM 措辞准确
- [ ] SM9-ID-KEM 到已有 SM9 安全分析/基础假设的映射已逐定理核对；否则保留模块化假设
- [ ] DoS、forward secrecy、full token leakage 边界明确
