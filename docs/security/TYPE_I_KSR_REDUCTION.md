# Type-I-KSR 机密性：从 V2 到 SM9-KEM，再到 Gap-τ-BCAA1_{1,2}

本文档给出 V2 在 **Known-Secret Public-Key Replacement (Type-I-KSR)** 模型下机密性证明的投稿级骨架。目标不是把受限模型包装成经典最强 Type-I，而是把当前模型中的“缺失身份因子”严格下钻到 Cheng 对 SM9-KEM 的基础困难假设，并把组合定理、随机预言机、解签密模拟和优势损失分开写清楚。

---

## 1. 记号与优势约定

令 `G1,G2` 为阶为素数 `q` 的加法群，`GT` 为乘法群，双线性对为

`e : G1 x G2 -> GT`。

取生成元 `P1 in G1, P2 in G2`。SM9 加密主秘密为 `s in Z_q^*`，主公钥为

`Ppub = [s]P1`。

本文与 Cheng 的 ID-IND-CCA2 定义保持一致，采用

`Adv(A) = |2 Pr[b'=b] - 1|`。

因此后文的常数均以此 advantage convention 为准；若论文正文改用 `|Pr[b'=b]-1/2|`，所有常数必须同步换算，不能混用。

域分离的 `H1`/SM3-KDF 在证明中按明确声明建模为随机预言机；这不是声称实际 SM3 与随机预言机等价。

---

## 2. V2 身份因子与标准 SM9-KEM 的精确代数对应

对接收身份 `ID_B`，令

`h_B = H1(ID_B || hid_enc)`，

则 V2/GmSSL 中

`Q_B = [h_B]P1 + Ppub = [h_B+s]P1`。

SM9 身份解密私钥为

`d_B = [s/(h_B+s)]P2`。

V2 的用户自选因子为

`x_B <- Z_q^*`,

`X_B = [x_B]Q_B`。

离线封装取

`rho <- Z_q^*`,

并计算

`U  = [rho]Q_B`,

`Z1 = g^rho`,

`Z2 = [rho]X_B = [x_B]U`,

其中

`g = e(Ppub,P2) = e(P1,P2)^s`。

接收端得到

`e(U,d_B)`
`= e([rho(h_B+s)]P1,[s/(h_B+s)]P2)`
`= e(P1,P2)^(rho s)`
`= Z1`。

因此

`Z1 = e(U,d_B)`

**正是标准 SM9-KEM 中的隐藏 pairing value `t`**。Cheng 的 SM9-KEM 写成：

`Q = [h+s]P1`,

`C1 = [z]Q`,

`t = e(Ppub,P2)^z = e(C1,d_ID)`。

对应关系逐项为：

| Cheng SM9-KEM | V2 |
|---|---|
| `ID` | `ID_B` |
| `h=H2RF1(ID||hid)` | `h_B=H1(ID_B||hid_enc)` |
| `Q=[h+s]P1` | `Q_B` |
| `C1=[z]Q` | `U=[rho]Q_B` |
| `d_ID=[s/(h+s)]P2` | `d_B` |
| `t=e(C1,d_ID)` | `Z1=e(U,d_B)=g^rho` |

这不是“结构类似”，而是 V2 身份因子对 SM9-KEM 核心隐藏量的直接复用。

---

## 3. Cheng 定理所使用的基础困难假设

Cheng, *Security Analysis of SM9 Key Agreement and Encryption*, INSCRYPT 2018, DOI `10.1007/978-3-030-14234-6_1`，Theorem 4 证明：

> SM9-KEM 在 `H2RF1` 与 `KDF2` 被建模为随机预言机时，在 `Gap-τ-BCAA1_{1,2}` 假设下满足 ID-IND-CCA2。

其具体归约给出：若攻击者优势为 `epsilon`，最多进行 `q_D` 次 decapsulation、`q1+1` 次身份哈希查询、以及对挑战身份的 `q2` 次 KDF 查询，则存在算法 `B` 解 `Gap-q1-BCAA1_{1,2}`，满足

`Adv_Gap-BCAA(B) >= epsilon/(q1+1)`，

运行时间满足

`t_B <= t_A + O(q2 * q_D * O_DBIDH)`，

其中 `O_DBIDH` 表示一次 DBIDH oracle 访问成本。

### 3.1 Gap-τ-BCAA1_{1,2}

给定

`P1, P2, [s]P1, h0,`

以及 `tau` 个不同的随机值 `h_i` 和

`[s/(h_i+s)]P2`，

并允许访问相应的 DBIDH oracle，目标是计算

`e(P1,P2)^(s/(h0+s))`。

### 3.2 为什么本文不能把它改写成“q-BDHI 假设”

Cheng 的定理明确是 **Gap-BCAA1**，并利用 DBIDH oracle 来检测候选 pairing value。文献中存在 BCAA/BDHI 之间在附加群同态条件下的关系，但这不等价于：

1. V2 已直接归约到普通 `q-BDHI`；
2. 可以删除 Gap oracle 而不付额外代价；
3. 在 SM9 使用的非对称 pairing 设置中可以无条件假设所需 `G2 -> G1` 高效同态存在。

因此投稿版应写

**Gap-q-BCAA1_{1,2} in the random-oracle model**，

而不是为了假设名称更熟悉而写成未经证明的 `q-BDHI`。

---

## 4. Type-I-KSR 中为什么附加用户因子不削弱 Cheng 归约

Type-I-KSR 的关键定义是：挑战会话使用的公开用户因子总具有

`X_B = [x_B]Q_B`

且 simulator/攻击者知道对应 `x_B`。

- 若公钥未被替换，challenger 自己生成 `x_B`，所以知道它；
- 若攻击者执行 KSR replacement，它必须提交已知秘密 `x'_B`，challenger 记录
  `X'_B=[x'_B]Q_B`。

因此对任意封装 `U`，都有

`Z2 = [x_B]U`

可由 simulator 直接计算。

V2 会话 KDF 输入可以抽象为

`H_K(Z1, Z2, aux)`，

其中

`aux = (ID_A, PK_A, ID_B, X_B, U, domain-separation)`。

在 Type-I-KSR 中，除 `Z1` 外的 `Z2` 与 `aux` 全部由公开数据和已知 `x_B` 可计算。因此从 SM9-KEM 的角度，V2 只是把

`KDF2(U,Z1,ID_B)`

扩展为

`H_K(U,Z1,ID_B, public_auxiliary_input)`。

随机预言机对公开附加输入的域扩展不会为攻击者提供计算隐藏 `Z1` 的新能力。

---

## 5. Auxiliary-input extension lemma

### Lemma 1

令 `SM9-KEM^aux` 与 Cheng 的 SM9-KEM 完全相同，但将 KDF 改为

`K = H_K(U,t,ID,aux)`，

其中 `aux` 在 encapsulation/decapsulation 时由 challenger 可有效计算，且不包含挑战身份私钥或隐藏 pairing value `t`。若 Cheng 的 SM9-KEM 在 Theorem 4 的条件下 ID-IND-CCA2 安全，则 `SM9-KEM^aux` 在相同 Gap-q1-BCAA1_{1,2} 假设下安全，并保留身份猜测的 `q1+1` 优势损失。

### Proof sketch with simulator details

复用 Cheng 的 `H1` 表和 Gap-BCAA challenge identity programming：

1. simulator 随机猜测第 `I in {1,...,q1+1}` 个不同身份查询为挑战身份；
2. 对该身份返回 challenge 值 `h0`，并把其身份私钥记录为 `perp`；
3. 对其他身份利用 Gap-BCAA 实例中的
   `[s/(h_i+s)]P2`
   正常回答 Extract；
4. `H_K` 表的索引从 Cheng 的 `(U,T,ID)` 扩展为
   `(U,T,ID,aux)`；
5. 若 `ID` 为特殊身份，simulator 使用同一个 DBIDH oracle 检测候选 `T` 是否等于
   `e(U,d*)`。该检测只依赖 `(Ppub,P2,Q*,U,T)`，与 `aux` 无关；
6. decapsulation table 相应改为由 `(U,ID,aux)` 索引，从而保证同一隐藏 `T` 在不同公开上下文中得到独立且一致的随机预言机输出。

故 Cheng simulator 的核心检测与提取步骤不变。

特别重要的是：**不需要随机猜测第几个 KDF 查询是正确查询。** Gap 假设提供的 DBIDH oracle 能逐个检测候选隐藏 pairing value，所以挑战身份 KDF 查询数 `q_K` 进入运行时间项，而不是形成 `1/q_K` 的 advantage loss。

---

## 6. V2-KEM 的 Type-I-KSR reduction

定义 `V2-KEM`：

- public state: `(ID_B,X_B)`；
- secret state: `(d_B,x_B)`；
- encapsulation: `U`, plus derived `(K_E,K_M)`；
- hidden identity factor: `Z1=e(U,d_B)`；
- known-secret user factor: `Z2=[x_B]U`；
- key derivation: `(K_E,K_M)=H_K(Z1,Z2,aux)`。

### Theorem 1 — V2-KEM Type-I-KSR ID-IND-CCA2

设 `A_K` 是 V2-KEM 的 Type-I-KSR ID-IND-CCA2 攻击者，优势为

`epsilon_K = Adv_V2-KEM,I-KSR(A_K)`。

设它最多产生 `q1+1` 个不同挑战候选身份哈希查询、`q_D` 个 decapsulation 查询、以及对挑战身份的 `q_K` 个 session-KDF 查询。则存在 `B_Gap` 解 `Gap-q1-BCAA1_{1,2}`，满足

`Adv_Gap-q1-BCAA(B_Gap) >= epsilon_K/(q1+1)`，

且运行时间为

`t_B = t_A + O(q_K * q_D * O_DBIDH) + poly(q1,q_D,q_K)`。

### Challenge construction

对被猜中的特殊身份 `ID_B*`，Gap-BCAA instance 给出 `h0`，但 simulator 不知道

`d_B*=[s/(h0+s)]P2`。

它选择

`y <- Z_q^*`

并令挑战

`U*=[y]P1`。

真实 V2 中应有

`U*=[rho]Q_B*=[rho(h0+s)]P1`。

因为在合法系统参数下 `h0+s != 0 mod q`，映射

`rho -> y=rho(h0+s)`

是 `Z_q^*` 上的双射，所以 `[y]P1` 与真实 `U*` 完全同分布。

Type-I-KSR simulator 已知挑战快照对应的 `x_B*`，故可直接算

`Z2*=[x_B*]U*`。

它随机返回 challenge key material `(K_E*,K_M*)`。若攻击者具有非零 KEM distinguishing advantage，则与 Cheng 证明相同，它必须以相应概率向 `H_K` 查询正确隐藏值

`T*=e(U*,d_B*)`

以及正确 `(Z2*,aux*)`。

DBIDH oracle 检测到正确 `T*` 后，simulator 输出

`(T*)^(1/y)`

即

`e(P1,P2)^(s/(h0+s))`，

从而解出 Gap-BCAA challenge。

---

## 7. KSR replacement oracle 的完整模拟

维护表

`L_PK[ID] = (X,x,version)`。

### Honest key creation

challenger 采样 `x <- Z_q^*`，计算

`X=[x]Q_ID`，

并记录 `x`。

### ReplaceKnownSecret(ID,x')

攻击者提交 `x' <- Z_q^*`，challenger 重新计算

`X'=[x']Q_ID`

并更新 `L_PK`。

若 API 允许攻击者同时提交 `X'`，challenger 必须验证

`X'=[x']Q_ID`

后才接受；否则模型已经超出 KSR，进入任意 replacement。

### Challenge snapshot

挑战生成时冻结

`(ID_B*,X_B*,x_B*,version*)`。

挑战禁止查询以该快照和挑战 `U*`/ciphertext equivalence class 为准。挑战后若模型允许再次 replacement，则新版本使用新的公开上下文和已知新 `x'`，不改变历史 challenge snapshot。

这一点必须在论文游戏中明确，否则“挑战后替换公钥再查询同一 ciphertext”会产生语义歧义。

---

## 8. 从 V2-KEM 到完整 signcryption 机密性

不要把 SM2 EUF-CMA 强行塞进机密性主归约。更干净的做法是把证明拆成：

1. **V2-KEM confidentiality**：上一节的 Gap-BCAA reduction；
2. **one-time DEM confidentiality/integrity**：`SM3-KDF/XOR + HMAC-SM3`；
3. SM2 signature 是对已经形成的 ciphertext transcript 的公开可验证认证层；在机密性 reduction 中 simulator 知道发送端 SM2 私钥，可以诚实生成 challenge signature。它不会增加攻击者对 KEM 隐藏量的知识。

### 8.1 V2 DEM

在给定均匀独立 `K_E,K_M` 和固定公开 context 时：

`stream = H_E(K_E,context,|M|)`，

`C=M xor stream`，

`mu=Encode(ID_A,ID_B,X_B,U,C)`，

`sigma=SM2.Sign(sk_A,mu)`，

`tau=HMAC-SM3_{K_M}(mu || sigma)`。

UnSC 按规范 transcript 验证 `sigma,tau` 后恢复明文。

若把 `H_E` 作为域分离随机预言机，把 HMAC-SM3 作为 PRF，则：

- 在攻击者未猜中 `K_E` 的正确 `H_E` 输入前，`stream` 是均匀 one-time pad；
- 把 HMAC 替换为随机函数后，对任何非 challenge transcript 的新有效 tag，至多支付 `q_D/2^256`；
- 猜中 256-bit `K_E` 的正确 hash query 至多支付 `q_E/2^256`。

因此可写一个保守界：

`Adv_FG-CCA_V2DEM`
`<= Adv_PRF_HMAC-SM3(B_mac) + q_D/2^256 + q_E/2^256`。

这里的 `q_D` 是 challenge-key DEM decryption attempts 上界，`q_E` 是相关加密流随机预言机查询上界。

### 8.2 为什么机密性主界不需要 SM2 EUF-CMA

若攻击者不能伪造 SM2，解密可接受集合只会更小；若它能够伪造 SM2，新 transcript 仍必须通过未知 `K_M` 下的 HMAC。故对 **IND-CCA confidentiality**，HMAC/DEM 完整性已经足够承担 challenge-key ciphertext modification 的 CCA 层。

SM2 EUF-CMA 应出现在 V2 的 **authentication/unforgeability theorem**，而不是为了让机密性证明看起来“用了所有组件”而重复计入。

同理，多会话 `multi-key HMAC` 损失主要属于完整 signcryption 的多会话 authenticity theorem；单个 challenge KEM key 对应的 one-time DEM confidentiality 可以通过标准 target-session reduction 使用单目标 HMAC PRF 项。

---

## 9. 完整 Type-I-KSR IND-CCA 优势界

由 identity-based KEM/DEM hybrid 的标准组合结构，可采用与 Cheng 文中 Theorem 1 相同的 advantage convention 写成：

`Adv_V2,I-KSR^IND-CCA(A)`
`<= 2 Adv_V2-KEM,I-KSR^ID-IND-CCA2(B_K)`
`   + Adv_V2DEM^FG-CCA(B_D)`。

结合 Theorem 1 的 V2-KEM reduction：

`Adv_V2-KEM,I-KSR(B_K)`
`<= (q1+1) Adv_Gap-q1-BCAA1_{1,2}(B_Gap)`。

再代入 DEM 界，得到投稿版可使用的保守主界：

`Adv_V2,I-KSR^IND-CCA(A)`
`<= 2(q1+1) Adv_Gap-q1-BCAA1_{1,2}(B_Gap)`
` + Adv_PRF_HMAC-SM3(B_mac)`
` + q_D/2^256`
` + q_E/2^256`
` + negl_encoding`。

其中：

- `q1+1`：身份哈希的候选挑战身份数；
- `q_K`：挑战身份 session-KDF 查询数，**进入 Gap solver 运行时间，不进入上述 advantage denominator**；
- `q_D`：challenge-target decapsulation/DEM decryption 相关查询数；
- `q_E`：加密流随机预言机查询数；
- `negl_encoding`：非法点、编码碰撞等已由 canonical encoding/validation 排除或可忽略的事件。

如果正文选择不直接引用 KEM/DEM 组合定理，而逐游戏证明，则也必须导出与上述结构一致的项；不能同时使用组合定理又重复计算同一 `Bad_mac` 事件。

---

## 10. Oracle 表与一致性要求

投稿证明至少显式定义：

- `L_H1`: `(ID,h,d_or_perp)`；
- `L_PK`: `(ID,X,x,version)`，KSR 下 `x` 始终由 simulator 已知；
- `L_K`: `(U,T,ID,Z2,aux,K_E,K_M)`；
- `L_D`: 特殊身份无法真实 decap 时的 `(U,ID,Z2,aux,K_E,K_M)` lazy-sampling 记录；
- `L_SC`: signcryption oracle 的完整 canonical transcript；
- `L_HE`: stream-KDF random-oracle table（若在 DEM proof 中显式模拟）。

对特殊身份：

1. `H_K` 候选 `T` 用 DBIDH oracle 检查是否为 `e(U,d*)`；
2. 若对应 `(U,ID,Z2,aux)` 已存在于 `L_D`，返回其中预先 lazy-sampled 的 key；
3. 否则新采样并双向登记 `L_K/L_D`；
4. decapsulation/UnSC 查询若此前没有正确 `H_K` query，可先 lazy-sample key，未来正确 `H_K` query 被 DBIDH 检测后必须返回同一值。

这正是 Cheng CCA2 simulator 的关键一致性机制在 V2 public auxiliary input 下的扩展。

---

## 11. 与 Type-II 证明的严格区分

Type-I-KSR：

- 缺 `d_B` / `Z1`；
- 知 `x_B`，所以 `Z2` 可算；
- 基础假设：`Gap-q-BCAA1_{1,2}`；
- DBIDH oracle 能检测正确 KDF hidden value，因此无 `1/q_K` query-guessing advantage loss。

Type-II：

- 知 KGC 主秘密 `s`，所以 `d_B` / `Z1` 可算；
- 缺用户秘密 `x_B` / `Z2`；
- 缺失因子是 `Q_B,U,X_B` 上的 CDH；
- 若坚持归约到普通 CDH 而没有 DDH/gap oracle，则 simulator 不能测试候选 `Z2`，所以关键 KDF query extraction 往往需要 query-index guessing 或其他技术。

**两个模型不能共享一个“统一 q_K 损失公式”。** Type-I 的 Gap-BCAA oracle 与 Type-II 的 plain-CDH reduction 能力不同。

---

## 12. 当前可以和不可以写进论文的结论

### 可以写

> Under the Type-I known-secret public-key replacement model, the receiver-side user secret corresponding to the active public factor is known to the adversary/simulator. Hence the user contribution `Z2=[x_B]U` is efficiently computable, while the missing identity contribution `Z1=e(U,d_B)` is exactly the hidden pairing value of SM9-KEM. By adapting Cheng's ID-IND-CCA2 reduction to include public auxiliary KDF inputs, V2-KEM reduces to the Gap-q-BCAA1_{1,2} assumption in the random-oracle model with the same identity-guessing loss. The number of challenge-identity KDF queries affects the reduction running time through DBIDH-oracle checks rather than adding a multiplicative query-guessing loss.

### 不可以写

- “V2 Type-I security is proved under q-BDHI.”
- “V2 is secure against arbitrary classical certificateless Type-I public-key replacement.”
- “SM3-KDF is a random oracle.”
- “The Type-I reduction loses a factor q_K in advantage.”（在本文采用 Cheng Gap-BCAA reduction 时不成立。）
- “SM2 EUF-CMA is necessary for the confidentiality reduction.”（它属于认证/不可伪造性证明；机密性主界由 KEM + authenticated DEM 承担。）

---

## 13. Reviewer checklist

投稿前逐项确认：

- [x] V2 `Z1` 与 Cheng SM9-KEM `t` 逐式对齐；
- [x] 明确 Cheng Theorem 4 的假设名称为 `Gap-q-BCAA1_{1,2}`；
- [x] 明确 advantage convention 为 `|2Pr[win]-1|`；
- [x] `q_K` 放在 reduction running time，而非无依据的优势分母；
- [x] KSR 中 challenger 对 active `X_B` 始终知道 `x_B`；
- [x] challenge public-key snapshot 与 post-challenge replacement 语义分离；
- [x] auxiliary KDF input 的 oracle table 索引完整；
- [x] confidentiality 与 authentication theorem 分开；
- [ ] 把本文件的 formal game 与最终论文符号逐字统一；
- [ ] 若论文声称 authenticity，再单独给出 SM2 EUF-CMA + multi-key HMAC 的不可伪造性定理；
- [ ] 最终排版时引用 Cheng Theorem 4 的页码/定理号和 DOI，避免只写二手概述。
