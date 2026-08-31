# V2 密码学审稿攻击矩阵

本文档把 V2 当作待投稿密码学方案进行敌对式审查。结论分为：已通过代码/CI 证据验证的实现性质、可以通过标准归约补齐的证明细节、以及目前仍属于理论残余风险的问题。不得把实现测试等同于困难性证明。

| ID | Concern | Severity | Attack / Failure Mode | Current Evidence | Resolution | Residual Risk |
|---|---|---:|---|---|---|---|
| R1 | Type-I-KSR 弱于经典 Type-I ReplacePublicKey | Major | 经典 certificateless Type-I 往往允许攻击者替换公开密钥，而不要求替换值必须写成已知 `x'` 的 `X'=[x']Q`；V2 仅覆盖 known-secret replacement。 | `native/tests/test_attacks.c` 只演示攻击者知道 `x'` 时可恢复 `Z2=[x']U`；相关 certificateless 文献指出 public-key replacement 模型存在多种强度。 | 论文、标题、摘要、定理统一写 **Known-Secret Public-Key Replacement (Type-I-KSR)**；明确其严格弱于一般任意替换模型，不使用 “standard Type-I” 或 “arbitrary replacement”。 | 这是当前最大理论风险。若目标期刊要求经典 CL-PKC 强模型，需要重新设计或增加更强模型证明。 |
| R2 | Type-I 将 SM9 身份因子安全性封装成模块化假设 | Major | 若直接定义“SM9-ID-KEM 安全”，可能被认为把核心困难重新命名而没有下钻到标准困难问题。 | Cheng, *Security Analysis of SM9 Key Agreement and Encryption* (INSCRYPT 2018, DOI `10.1007/978-3-030-14234-6_1`) 对 SM9 加密/密钥协商做 ROM 形式分析；本轮检索尚未核实其每一条定理与 V2 所需 KEM 游戏的精确假设映射。 | 投稿前逐定理核对 Cheng 2018/标准相关证明。如果能黑盒映射，给出定理号和基础假设；若不能，正文明确保留 `SM9-ID-KEM` **模块化假设**，并降低安全定理措辞。 | 在未核对完整证明之前，不得声称“已归约到 q-BDHI”。 |
| R3 | Type-II CDH 嵌入可能被恶意 KGC 识别 | Major | 若强制编程 `H1(ID*)=1-s` 使 `Q*=P`，Type-II 已知 `s`，可识别挑战身份分布异常。 | 当前证明已改为缩放嵌入：诚实采样 `h*`，`c=h*+s`; `Q*=cP,U*=c[a]P,X*=c[b]P,Z2*=c[ab]P`。 | 保留缩放嵌入，并显式计入 `Pr[c=0]=1/q`；归约成功后输出 `[c^{-1}]Z2*=[ab]P`。 | 仍需完整写出每个 oracle 表和查询一致性。 |
| R4 | Type-II 正确 KDF 查询的 guess-and-abort 损失 | Major | 模拟器不知道 `Z2*`，挑战密钥先随机；若攻击者从未查询正确 KDF 输入，视图独立；若查询，归约需命中正确查询。 | 设计规格已要求挑战身份猜测与 KDF 查询索引猜测；CI 实现不构成这一概率论证明。 | 定义事件 `E_id`, `E_c`, `E_K`; 写出 `N_ID`、`q_K` 和 bad events，最终优势界中显式出现猜测损失。 | 具体常数在游戏序列完全确定前不能提前冻结。 |
| R5 | HMAC 是多会话多密钥，而非单密钥 UF-CMA/PRF | Major | 每个 signcryption token 派生独立 `K_M`；裸写单密钥 HMAC advantage 缺少 multi-user 损失。 | native 实现每个 token 独立派生 `K_M`; tamper tests 验证 MAC 绑定行为。 | 首选在论文定义 multi-key HMAC PRF/UFCMA advantage；备选方案是猜测目标会话并支付最多 `q_sc` 量级损失。 | 代码测试不证明 HMAC 多用户归约；需要论文形式化补齐。 |
| R6 | 同消息的新随机化 SM2 签名不属于普通 EUF-CMA 新消息伪造 | Major | 对已经签过的 `mu` 产生不同合法 SM2 `(r,s)`，不能直接作为 ordinary EUF-CMA 事件。 | V2 的 `tau=HMAC_{K_M}(mu||sigma)` 明确绑定具体签名；tamper signature/tag 均被拒绝。 | 普通消息级 EUF-CMA 仅处理“新 `mu`”；同 `mu` 替代随机化签名放到 CCA/HMAC binding bad event。 | 不声明 strong ciphertext unforgeability。 |
| R7 | SM3-KDF 与 ROM 的措辞可能过强 | Major | “使用 SM3-KDF”与“随机预言机”不是同一事实。 | 实现使用域分离的 SM3 KDF；证明草稿使用 ROM。 | 统一写：**The domain-separated SM3-KDF instances are modeled as independent random oracles for the proof.** | 不得声称标准 SM3-KDF 已被证明等价于随机预言机。 |
| R8 | 公钥替换后的机密性不等于可用性 | Moderate | Type-I 将 `X_B` 替换成攻击者控制的 `X'_B` 后，诚实 B 不持有 `x'_B`，可能无法解密，形成 DoS。 | Type-I-KSR 代码演示只验证攻击者知识路径，不声称 availability。 | 安全边界明确：本文声明 replacement 下攻击者不能恢复挑战明文，不声明通信可用性；DoS 不在机密性定理内。 | 应避免“抗公钥替换后仍可正常通信”这类措辞。 |
| R9 | XOR + KDF 的 DEM 需要明确 CCA 组合逻辑 | Major | 单纯 `C=M xor stream` 没有独立完整性；CCA 安全必须依赖 `tau` 与签名门控。 | native UnSC 顺序：点验证 -> X_B 匹配 -> SM2 -> KEM -> HMAC -> XOR；所有字段单独篡改均拒绝。 | 证明中把 DEM 看作 ROM/PRF 生成的 one-time stream，并通过 HMAC transcript integrity + signature gating 处理 CCA 查询。 | 需要把“challenge core 的新有效 transcript”与 bad events 对齐，避免循环论证。 |
| R10 | 完整 offline token 泄漏暴露 SM2 nonce `k` | Major | token 中保存完整 SM2 precompute `(k,x_R)`；若攻击者得到 token 并观察签名，可危及长期私钥。 | token 生命周期已强制 `READY -> CONSUMED`，用后清零，重复使用被测试拒绝。 | 论文明确采用 **secure one-time offline token assumption**，不声明 token leakage resilience；侧信道/HSM 属工程防护。 | 仍不抵抗完整 token 泄漏。 |
| R11 | 同一 token 的异常/SM2 retry 不得恢复 READY | Major | 若失败后回滚 token，会导致 nonce/session material 重用。 | native `v2_online_signcrypt` 在消息相关密码运算前设置 `CONSUMED`，任何路径结尾清除 `K_E,K_M,k`；duplicate-use test 通过。 | 保持 fail-closed 生命周期；论文写“异常也销毁”。 | 进程崩溃/持久化恢复需由真实部署的原子存储保证。 |
| R12 | 实验性能数据可能混合不同平台/commit | Major | 手工复制或多次覆盖 CSV 会使论文数值不可追踪。 | CI artifact `9754694893` 已独立验证：4 sizes × 9 phases × 50 = 1800 raw rows；单一 V2/GmSSL SHA；summary 可从 raw 精确重算。 | 论文区分 `CI reproducibility benchmark` 与最终 `submission benchmark`；最终 Ryzen 数据必须同样保存 raw/summary/env/log。 | 当前 CI 数据不可替代 Ryzen 7 8845H 投稿表。 |

## 当前审稿结论

- **实现层面**：native GmSSL 3.x 原型已经通过 round-trip、篡改拒绝、错误密钥、非法点、token 重用和知识路径测试，并已产生可追溯 CI benchmark artifact。
- **证明层面**：Type-II 缩放 CDH 嵌入比早期版本更合理；HMAC multi-key、KDF query guessing、ROM 表一致性仍需在正文写成完整优势界。
- **投稿风险排序**：`R1 Type-I-KSR 模型强度` > `R2 SM9-ID-KEM 基础假设映射` > `R4/R5 归约损失细化` > 其余可修复项。

因此，在未解决 R1/R2 之前，不应把稿件描述为“达到经典 CL-PKC 最强 Type-I 模型”或“机密性已严格归约到 q-BDHI”。
