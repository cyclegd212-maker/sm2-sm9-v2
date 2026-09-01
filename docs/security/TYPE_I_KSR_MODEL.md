# Type-I-KSR：已知秘密公钥替换模型

## 1. 模型定义

V2 不声称达到经典 certificateless public-key cryptography 中最强的任意 `ReplacePublicKey` 模型。本文采用 **Known-Secret Public-Key Replacement (Type-I-KSR)**：

1. 攻击者不知道 KGC 主私钥 `s`，不得获得挑战身份的 SM9 身份私钥 `d_B`；
2. 攻击者可以选择任意 `x'_B in Z_q^*`，并把接收者公开因子替换为
   `X'_B=[x'_B]Q_B`；
3. 攻击者被显式赋予/本来就知道 `x'_B`，因而对挑战封装 `U=[rho]Q_B` 可以计算
   `Z'_2=[x'_B]U=[rho]X'_B`；
4. 挑战会话密钥仍同时依赖 `Z_1=g^rho` 与 `Z'_2`，因此 Type-I-KSR 的机密性核心是：即使用户因子完全落入攻击者控制，身份因子仍不可恢复。

这一模型比“只能替换但不知道对应秘密值”的弱攻击者更强，但比允许替换为任意群元素、且不要求存在/已知相对于 `Q_B` 的离散对数的经典强 Type-I 模型更受限。

## 2. 为什么单独定义 KSR

V2 删除 PoP/RA/epoch 后，不再依靠注册层阻止替换。KSR 的工程语义是：攻击者建立一个由自己完整控制的用户侧密钥因子，并诱导发送者使用该替换记录。我们直接给攻击者替换秘密 `x'_B`，而不是通过 PoP “限制”其能力。

这使安全目标非常明确：

- 攻击者对 `Z_2` 没有任何计算障碍；
- 机密性只剩对 `Z_1` 的保护；
- 因而双因子设计的“互补缺失”结构可以单独检验。

## 3. 与经典 Type-I 的关系

certificateless security-model 文献反复指出 public-key replacement 的建模细节会改变安全强度，并存在多类 Type-I adversary。若方案把“替换公钥”与“攻击者知道相应私钥”混为一谈，就可能得到超出实际模型的安全结论。

因此本文必须使用以下措辞：

> V2 achieves confidentiality against a Type-I known-secret public-key replacement adversary (Type-I-KSR), not against the strongest arbitrary public-key replacement adversary of classical certificateless cryptography.

禁止写：

- “secure against standard Type-I adversaries” （除非随后明确定义是本文 KSR，而不是经典最强模型）；
- “arbitrary public-key replacement resistance”；
- “full certificateless Type-I security”。

## 4. 挑战游戏与状态版本

对每个身份维护当前用户公开因子状态

`L_PK[ID]=(X_B,x_B,version)`。

KSR replacement 接口应为

`ReplaceKnownSecret(ID,x'_B)`，

challenger 自行计算

`X'_B=[x'_B]Q_B`。

如果实现/形式模型允许攻击者同时提交 `X'_B`，必须验证该等式；否则攻击能力已经扩展成本文未证明的 arbitrary replacement。

挑战生成时冻结快照

`(ID_B^*,X_B^*,x_B^*,version^*)`。

攻击者允许知道 `x_B^*`，但：

- 不得提取 `d_B^*`；
- 不得获得同时恢复两个因子的完整挑战接收私钥；
- challenge ciphertext 本身及 canonical-equivalent 禁止查询不能提交给 UnSC；
- 若挑战后允许再次 replacement，新 `version` 不改变历史 challenge snapshot 的等价关系。

显式版本化可避免“挑战后换公钥，再把旧 challenge 当成新上下文提交”的模型歧义。

## 5. 基础困难假设已经完成下钻

对挑战身份

`h_B=H1(ID_B||hid_enc)`，

`Q_B=[h_B+s]P1`，

`d_B=[s/(h_B+s)]P2`，

`U=[rho]Q_B`。

V2 身份因子满足

`Z_1=e(U,d_B)=e(P1,P2)^(rho s)=g^rho`。

它与 Cheng, *Security Analysis of SM9 Key Agreement and Encryption*, Theorem 4（INSCRYPT 2018, DOI `10.1007/978-3-030-14234-6_1`）中 SM9-KEM 的隐藏 pairing value `t` 完全一致。

Cheng 的定理在 `H2RF1`、`KDF2` 被建模为随机预言机时，把 SM9-KEM 的 ID-IND-CCA2 安全归约到

**Gap-q-BCAA1_{1,2}**，

并给出身份猜测损失 `q1+1`。其 DBIDH oracle 能逐个测试挑战身份的 KDF 候选隐藏值，因此 KDF 查询数进入 reduction running time，而不是额外形成 `1/q_K` advantage loss。

Type-I-KSR 中 challenger 始终知道 active user factor 的 `x_B`，所以

`Z_2=[x_B]U`

可直接计算。V2 的 session KDF 只是把 Cheng KDF 的输入扩展为

`H_K(Z_1,Z_2,public_aux)`。

完整 auxiliary-input extension、decapsulation/KDF oracle 一致性和主优势界见：

`docs/security/TYPE_I_KSR_REDUCTION.md`。

因此当前可声明的基础假设是：

> **Gap-q-BCAA1_{1,2} in the random-oracle model.**

仍不得改写成“普通 q-BDHI”，因为 Cheng 的证明显式使用 Gap/DBIDH oracle；删除 gap oracle 或依赖额外群同态都需要新的论证。

## 6. DoS 边界

替换成 `X'_B` 后，原合法用户只知道旧 `x_B`，因此未来发往 `X'_B` 的 ciphertext 可能无法由原用户解开。这是 availability/DoS 问题，不与 confidentiality 定理矛盾。

本文只声明：

> 即使攻击者已经成功控制挑战使用的用户公开因子，并知道对应 `x'_B`，它仍不能仅凭这些信息恢复完整会话密钥和挑战明文。

本文不声明：

> 公钥被恶意替换后，原接收者仍能继续正常解密。

## 7. 投稿策略

如果后续无法证明经典任意 Type-I 模型，标题、摘要、贡献和定理均应出现 `known-secret public-key replacement` 限定词。若目标期刊明确要求标准 CL-PKC Type-I，则应把“加强模型”视为新密码构造任务，而不是通过措辞把 KSR 包装成经典 Type-I。

当前 Type-I-KSR 的理论剩余工作已经从“寻找基础假设”缩小为：

1. 把 `TYPE_I_KSR_REDUCTION.md` 的符号与最终论文 game 逐字统一；
2. 固定 KEM/DEM 组合定理的最终引用与常数；
3. 独立完成 signcryption authenticity theorem（SM2 EUF-CMA + multi-key HMAC），不要与 confidentiality 主界重复计项。
