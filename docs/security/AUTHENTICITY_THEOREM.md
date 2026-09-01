# V2 独立认证定理：SM2 EUF-CMA + multi-key HMAC

本文档把“消息新鲜性不可伪造”与“已签 transcript 的替代随机化签名绑定”严格分开，形成一个不与 IND-CCA 证明混算的独立 authenticity theorem。

## 1. 为什么需要两层认证定义

V2 的接收顺序是：

1. 公开验证 SM2 signature `sigma` on `mu`；
2. 恢复会话 key；
3. 验证 `tau=HMAC_{K_M}(Enc(MAC,mu,sigma))`。

标准 SM2 EUF-CMA 只排除“新消息 `mu` 上的有效签名”。它不自动排除：对一个已经签过的 `mu`，攻击者输出另一个有效随机化签名 `sigma' != sigma`。因此：

- message-level unforgeability 由 SM2 EUF-CMA 单独承担；
- same-transcript signature-substitution binding 由 HMAC 对具体 `sigma` 的绑定承担。

## 2. Message-EUF 游戏

攻击者访问 Signcrypt oracle，最终输出被 UnSC 接受的 `CT*`。若其 canonical signing message `mu*` 从未作为目标 sender 的 Signcrypt/挑战签名消息出现，则记为 `Forge_new`。

### Theorem A — Message-EUF

存在 SM2 EUF-CMA forger `B_sig` 使

`Pr[Forge_new] <= Adv_SM2^EUF-CMA(B_sig)`。

证明是直接的：UnSC 在任何 KEM/HMAC/解密操作之前先验证 `(mu*,sigma*)`；若 `mu*` 新且验证通过，则 `(mu*,sigma*)` 本身就是底层 SM2 新消息伪造。Type-I-KSR 的 receiver public-key replacement 与 Type-II 的 KGC master secret 均不提供 sender 的 SM2 signing key。

这一定理不需要 HMAC 项，也不声称 SM2 strong unforgeability。

## 3. Transcript-AUTH 游戏

为了单独刻画 HMAC 的作用，定义更强但明确限定的 `TAUTH`：攻击者获胜当且仅当

- `CT*` 被 UnSC 接受；
- `CT*` 不是 Signcrypt oracle 曾返回的逐字节 ciphertext；
- target sender secret 未泄漏。

定义 `KeyAsk_i`：对某个 Signcrypt record `i`，攻击者在输出 forgery 前曾查询 exact session-KDF input

`H_K(Z1_i,Z2_i,ctx_i)`，

从而得到该 record 的 `(K_E_i,K_M_i)`。令 `KeyAsk` 表示最终 forgery 若复用某个旧 `mu_i` 时，对应 `KeyAsk_i` 发生。

`KeyAsk` 必须显式暴露：如果 receiver-side KEM key 已经被恢复，HMAC key 当然不再是秘密。把这种情形仍然记成“HMAC 伪造”是不正确的。

## 4. Multi-key HMAC 游戏

Signcrypt 的不同 session-KDF 输入产生独立随机 `K_M`；若两个 session 恰有相同 KDF 输入，则把它们视为同一个 MAC key instance，并允许该 instance 有多次 tag 查询。故全局最多有 `q_sc` 个独立 MAC key instances。

定义 `Adv_HMAC^{mu-UF-CMA}(B_mac)` 为 multi-user/multi-key MAC unforgeability advantage：攻击者可在多个独立 key instance 下获取 tag，最终必须在某个未泄漏 key 下对该 key 从未 tagged 的 MAC message 输出有效 tag。

Morgan–Pass–Shi (ASIACRYPT 2020, DOI `10.1007/978-3-030-64837-4_24`) 明确讨论了从 single-user MAC 到 multi-user MAC 的经典随机目标实例 guessing reduction：若有 `ell` 个实例，则朴素 reduction 的成功概率损失为 `ell`。因此若目标期刊只接受单密钥 HMAC UF-CMA 记号，可保守写

`Adv_HMAC^{mu-UF-CMA} <= q_sc * Adv_HMAC^{UF-CMA}`。

本文优先使用 multi-key advantage 记号，避免在每个公式里重复目标会话猜测。

## 5. Theorem B — Transcript authenticity decomposition

设 `Forge_T` 是 `TAUTH` 获胜事件，则存在 `B_sig,B_mac` 使

`Pr[Forge_T]
 <= Adv_SM2^EUF-CMA(B_sig)
  + Adv_HMAC^{mu-UF-CMA}(B_mac)
  + Pr[KeyAsk]
  + negl_enc`。

其中 `negl_enc` 只覆盖 canonical encoding/point-validation 假设外的可忽略实现异常；若规范编码被建模为严格单射且非法点确定性拒绝，可取 0。

### Proof

取任意被接受、且不是历史 Signcrypt 输出的 `CT*=(X*,U*,C*,sigma*,tau*)`，记 canonical signing message 为 `mu*`。

#### Case 1 — `mu*` 从未被签过

直接触发 `Forge_new`，归约到 SM2 EUF-CMA。

#### Case 2 — `mu*=mu_i` for some Signcrypt record `i`

由于 canonical encoding 对 `(ID_A,P_A,ID_B,X,U,C)` 单射，`mu*=mu_i` 强制 ciphertext core `(X*,U*,C*)` 与 record `i` 完全相同，因此恢复出的 session key 也是 record `i` 的 `K_M_i`。

- 若 `sigma*=sigma_i`：HMAC 是确定性函数；接受要求 `tau*=tau_i`。于是整个 `CT*` 与历史输出逐字节相同，违反 TAUTH 的“new ciphertext”获胜条件。
- 因而任何新的、被接受的 ciphertext 必须满足 `sigma* != sigma_i`。

此时 MAC input

`m* = Enc(MAC,mu_i,sigma*)`

与历史 tagged input

`m_i = Enc(MAC,mu_i,sigma_i)`

不同。若 `not KeyAsk_i`，对应 `K_M_i` 仍是未泄漏 session key；攻击者输出有效 `tau*` 即构成该 key instance 下对新 MAC message 的伪造。跨所有 session，这正是 multi-key HMAC UF-CMA 事件。

两类互斥情形并集得到主界。

## 6. Single-key corollary

若只使用标准单密钥 HMAC UF-CMA 假设，则随机猜最终被攻击的 session key instance。最多 `q_sc` 个 instance，因此

`Pr[Forge_T]
 <= Adv_SM2^EUF-CMA(B_sig)
  + q_sc * Adv_HMAC^{UF-CMA}(B_mac')
  + Pr[KeyAsk]
  + negl_enc`。

该 `q_sc` 线性损失不是 V2 特有；它是普通 single-user -> multi-user MAC guessing reduction 的标准代价。

## 7. HMAC-SM3 假设的文献定位

V2 不声称“SM3 自动等价于 PRF”。论文采用模块化假设：HMAC-SM3 在随机 256-bit key 下满足所需 PRF/UF-CMA 性质。

HMAC 的经典证明基础可引用 Mihir Bellare, “New Proofs for NMAC and HMAC: Security without Collision Resistance,” Journal of Cryptology 28(4):844–878, DOI `10.1007/s00145-014-9185-x`：该工作给出 HMAC PRF/MAC 的构造性安全分析，但具体实例化到 SM3 仍是本文的算法假设，而不是论文自行完成的 SM3 压缩函数证明。

## 8. SM2 假设的文献定位

V2 把标准 SM2 作为模块化签名原语，而非重新证明 SM2。Zhenfeng Zhang, Kang Yang, Jiang Zhang, Cheng Chen, “Security of the SM2 Signature Scheme Against Generalized Key Substitution Attacks,” SSR 2015, DOI `10.1007/978-3-319-27152-1_7`，给出了 SM2 的 formal analysis，并在其明确的 generic-group/hash/conversion 条件下证明 EUF-CMA。论文应引用该结果并准确写“we assume the standardized SM2 instantiation satisfies the stated EUF-CMA property”，不要无条件声称标准文本本身已经在任意模型下证明。

## 9. 与 Type-I/Type-II receiver-side key hiding 的关系

`Theorem B` 有意把 `Pr[KeyAsk]` 暴露为模块化项。

- Type-I-KSR：攻击者知道 active `x_B`，但 exact `H_K` 仍需要隐藏 SM9 identity factor `Z1`；其 key-hiding 可由本文 Gap-q-BCAA1_{1,2} 路径进一步界定。
- Type-II：攻击者知道 `Z1`，但 exact `H_K` 需要 user factor `Z2`；其 key-hiding 与 G1-CDH 路径相关。

如果论文只声明当前 message-level EUF-CMA，则完全不需要展开 `KeyAsk`/HMAC：Theorem A 已足够。只有当论文额外声明“任何新 ciphertext/transcript binding authenticity”时，才使用 Theorem B。

## 10. 与 IND-CCA 的去重

- Type-II IND-CCA 为了模拟 challenge-user UnSC，只对 **challenge HMAC key** 使用 PRF hybrid + random-tag guessing。
- 本 theorem 的 multi-key UF-CMA 用于全局 transcript authenticity。
- 两者是不同安全目标、不同 reduction；不要把 `Adv_HMAC^{mu-UF}` 再重复加入 Type-II confidentiality 的 `delta_II`。

## 11. Reviewer checklist

- [x] 普通 SM2 EUF-CMA 与 strong unforgeability 严格区分；
- [x] 新 `mu` -> SM2 EUF-CMA；
- [x] 旧 `mu` + 新 `sigma` -> HMAC 新消息伪造；
- [x] 显式处理 `KeyAsk`，不假装 KDF-derived MAC key 永远隐藏；
- [x] multi-key HMAC 与 single-key `q_sc` guessing corollary 均给出；
- [x] HMAC PRF 文献与 multi-user MAC 文献分开引用；
- [x] 与 Type-II confidentiality 的 challenge-key HMAC PRF 项去重。
