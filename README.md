递归解析加了签名校验，结果一条被篡改的委派记录仍然能一路验到根：名称标签切分不去尾点，根区名称多出一层导致标签数错；通配符展开后标签数不加一，通配记录被误判为精确匹配；摘要算法按当前默认值计算而不按记录声明，算法迁移后全链失配；摘要比较用前缀比较，短摘要可命中；有效期只比较终止时间，未生效签名被接受；有效期允许起始等于终止，零长度窗口通过；链验证从信任锚开始而不是从叶子往锚回溯，中间层可被跳过；链验证遇到失败继续向下走，返回最后一个失败点而不是第一个；否定证明只检查名字不在区间内即放行，未检查区间是否由权威签名保护；批量验证复用当前链上下文，第二个查询沿用第一个查询的验证状态。dnssec/chain.py 是核心，tests/test_chain.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

运行方式
在仓库根目录执行：
    pytest tests -q

预期输出为 15 failed，无 error，无 collection error。测试不联网、不使用随机数，所有 DNS 数据均由参数注入，不进行真实 DNS 查询。

自检输出尾部示例：
    15 failed in 0.xxs

字段表

| 字段 | 取值 |
| --- | --- |
| 领域 | 安全 |
| 方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 技术栈 | Python 3, pytest |
| 外部依赖 | 无外部依赖 |

tests 约束
tests/test_chain.py 恰好包含 15 个测试，交付后不可修改。实现者只能补全 src/dnssec/chain.py 中的 8 个桩，不得通过改测试、删测试、跳过测试或放宽断言获得通过。测试使用构造的 DNS 记录、DS、DNSKEY、RRSIG 和 NSEC，不联网、不读取随机数、不进行真实 DNS 查询。

src 布局说明
本仓库采用 src 布局，实现包位于 src/dnssec，测试位于 tests。tests/conftest.py 只负责把仓库根的 src 目录加入 sys.path，使 from dnssec import chain 可用。核心实现文件是 src/dnssec/chain.py，唯一测试入口是 tests/test_chain.py。chain.py 恰好提供 8 个公开桩：parse_rrset、name_labels、ds_matches、check_validity、check_labels、verify_chain、denial_proof、chain_batch。实现必须保持这些函数的签名和返回结构，不得引入网络访问或外部依赖。

数据契约
委派链按叶子到信任锚排列。每层包含 zone、dnskey、ds、rrset、rrsig；ds 是父区域为本层 DNSKEY 发布的委派签名摘要，信任锚层的 ds 为 None。DNSKEY 包含 name、key_tag、algorithm、flags、protocol、public_key；DS 包含 key_tag、algorithm、digest_type、digest；RRSIG 包含 key_tag、algorithm、labels、inception、expiration、signer、signature；NSEC 包含 owner、next、types、authoritative、rrsig。digest 和 public_key 均为十六进制字符串，时间均为整数秒。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

