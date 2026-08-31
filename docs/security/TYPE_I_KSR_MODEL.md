# Type-I-KSR：已知秘密公钥替换模型

## 1. 模型定义

V2 不声称达到经典 certificateless public-key cryptography 中最强的任意 `ReplacePublicKey` 模型。本文采用 **Known-Secret Public-Key Replacement (Type-I-KSR)**：

1. 攻击者不知道 KGC 主私钥 `s`，不得获得挑战身份的 SM9 身份私钥 `d_B`；
2. 攻击者可以选择任意 `x'_B in Z_q^*`，并把接收者公开因子替换为
   `X'_B=[x'_B]Q_B`；
3. 攻击者被显式赋予 `x'_B`，因而对挑战封装 `U=[rho]Q_B` 可以计算
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

certificateless security-model 文献反复指出 public-key replacement 的建模细节会改变安全强度，并存在多类 Type-I adversary。相关 cryptanalysis 也展示了：若方案把“替换公钥”与“攻击者知道相应私钥”混为一谈，可能得到过强的安全结论。

因此本文必须使用以下措辞：

> V2 achieves confidentiality against a Type-I known-secret public-key replacement adversary (Type-I-KSR), not against the strongest arbitrary public-key replacement adversary of classical certificateless cryptography.

禁止写：

- “secure against standard Type-I adversaries” （除非随后明确定义是本文 KSR，而不是经典最强模型）；
- “arbitrary public-key replacement resistance”；
- “full certificateless Type-I security”。

## 4. 挑战游戏的关键限制

挑战身份 `ID_B^*` 的替换公钥若为 `X_B^*=[x_B^*]Q_B^*`，攻击者允许知道 `x_B^*`。但是：

- 不得提取 `d_B^*`；
- 不得同时获得会使两个因子均可恢复的完整接收私钥；
- 解签密查询受标准挑战新鲜性限制；
- 挑战 ciphertext 本身及按本文等价关系定义的禁止查询不能提交给 UnSC oracle。

## 5. DoS 边界

替换成 `X'_B` 后，原合法用户只知道旧 `x_B`，因此未来发往 `X'_B` 的 ciphertext 可能无法由原用户解开。这是 availability/DoS 问题，不与 confidentiality 定理矛盾。

本文只声明：

> 即使攻击者已经成功控制挑战使用的用户公开因子，并知道对应 `x'_B`，它仍不能仅凭这些信息恢复完整会话密钥和挑战明文。

本文不声明：

> 公钥被恶意替换后，原接收者仍能继续正常解密。

## 6. 投稿策略

如果后续无法证明经典任意 Type-I 模型，标题、摘要、贡献和定理均应出现 `known-secret public-key replacement` 限定词。若目标期刊明确要求标准 CL-PKC Type-I，则应把“加强模型”视为新密码构造任务，而不是通过措辞把 KSR 包装成经典 Type-I。
