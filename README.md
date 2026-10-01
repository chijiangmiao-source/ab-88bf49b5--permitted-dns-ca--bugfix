# 遥测服务证书链离线复核工具

地面接收终端接入新的遥测服务证书时，安全工程师需要在**完全离线**的浏览器页面中确认：
证书包能否以**指定主机名、指定验证时刻**建立一条终止于指定信任锚的**受限信任链**，
避免错误的中间证书借助域名通配、名称约束遗漏或 `pathLenConstraint` 绕过获得信任。

本工具零后端、零第三方运行时依赖：全部 DER 解析、WebCrypto 验签与链构造都在
页面启动的 **Web Worker** 中完成；粘贴的证书不会离开浏览器。

## 接受的证书配置（强约束）

- 仅 **X.509 v3**（`version INTEGER = 2`，带标准扩展域）
- 签名算法 **ecdsa-with-SHA256**（OID `1.2.840.10045.4.3.2`），TBS 内外算法 OID 必须一致且无多余 parameters
- 公钥 **id-ecPublicKey**（`1.2.840.10045.2.1`）+ **P-256 / prime256v1**（`1.2.840.10045.3.1.7`）
- EC 公钥为 65 字节未压缩点（`04‖X‖Y`）
- 签名 BIT STRING 内嵌的 DER `SEQUENCE{r INTEGER, s INTEGER}` 会被精确转换为 WebCrypto
  要求的 64 字节裸 `r‖s`（短整数左补零，33 字节符号八位组去符号位）
- 出现**无法识别的关键扩展**（critical=true）一律拒绝

## 核验内容（逐级）

1. **DER 结构解析**——截断 DER / 长度越界 / 非法时间 / 非 v3 等直接定位到具体证书与字节偏移
2. **候选链构造**——从“SAN 含目标主机名”的每一张叶证书出发，按
   issuer/subject 的 **Name DER 字节相等**向锚上溯；证书池无序、最多 7 张
3. **签名**——以候选签发者 P-256 公钥验证**保留下来的原始 `tbsCertificate` TLV 字节**
4. **有效期**——notBefore/notAfter 覆盖验证时刻（UTCTime 世纪折转 1950–2049，严格日历校验）
5. **BasicConstraints cA**——叶证书不得 cA=true；签发者必须存在扩展且 cA=true
6. **keyUsage**——CA 须含 keyCertSign；叶证书若带 keyUsage 须含 digitalSignature
7. **pathLenConstraint**——统计每个 CA 路径下方的**非自签发**中间证书数量
8. **名称约束**——自锚向下累积每个 CA 的 DNS permitted/excluded，应用到所有下级证书的
   dNSName（叶级额外对目标主机名求值）；excluded 命中即拒，permitted 非空时须至少命中一条
9. **SAN 主机名**——精确匹配 + 仅允许最左整标签通配 `*.domain`；回退 CN 不予接受
10. **循环签发**——路径内重复出现同一证书判为循环

**多链选择**：若多条候选链全部通过，按“叶 → 锚”各级证书 **SHA-256 摘要字典序**
取最小向量，稳定选出同一条，并在页面说明共有几条候选链。

任何失败都会报告**首个失败环节**（层级、证书主体、SHA-256、失败检查项与原因），
并清除上一次成功结论；“核验尝试明细”可展开查看全部尝试过的边。

## 目录结构

```
src/app/
  index.html / styles.css / main.js   页面（采集、渲染、清空草稿）
  worker.js                           Web Worker 入口（消息协议）
  crypto/
    der.js        DER TLV 解码器（保留原始 tbsCertificate 字节与偏移）
    oids.js       OID 常量
    x509.js       X.509 v3 解析与配置画像（profileErrors）
    ecdsa.js      ECDSA DER 签名 -> 64 字节 raw r||s
    dns.js        DNS 规范化、SAN 匹配、RFC 5280 名称约束
    webcrypto.js  SHA-256 / P-256 公钥导入 / ECDSA 验签
    verifier.js   候选链 DFS、逐级核验、多链选择、失败定位与报告
scripts/
  der-encoder.js / cert-builder.js   仅用于生成测试夹具的 DER/证书编码器
  generate-fixtures.mjs              生成全部边界夹具与页面内置示例
  build-page.mjs                     页面构建（语法/引用检查 + 拷贝到 dist）
  server.mjs                         零依赖静态服务器（含 /healthz）
  verify.mjs                         一次性验收编排（测试+构建+HTTP 冒烟）
test/              node:test 逻辑测试（DER/ECDSA/DNS/全链场景/Worker 协议）
docker/nginx.conf  页面服务与健康响应配置
Dockerfile         多阶段：build / web / verify
docker-compose.yml web（可配宿主端口）+ verify（一次性，退出码报告）
```

## 本地运行（Node ≥ 20，无需安装依赖）

```bash
npm run gen:fixtures      # 生成测试夹具与内置示例
npm test                  # 逻辑测试
npm run build             # 构建到 dist/
PORT=8080 npm run serve   # 提供页面；健康检查 GET /healthz
npm run verify            # 一次性验收：夹具 -> 测试 -> 构建 -> 起服 -> HTTP 冒烟，退出码报告
```

打开 `http://localhost:8080/`，粘贴信任锚与无序证书（PEM 或裸 DER Base64，可混贴），
填入目标 DNS 与验证时刻（按 UTC 解释）后“提交复核”；“清空草稿”重置全部输入与旧结论；
“填入内置示例”加载一条有效链。

## Docker / Compose

```bash
# 页面（宿主端口可配）
HOST_PORT=9090 docker compose up web --build
# 健康响应
curl -s http://localhost:9090/healthz
# 一次性验收容器：围绕有效链与受限域名拒绝场景跑完后退出
docker compose run --rm verify; echo "exit=$?"
```

`verify` 容器内顺序执行：夹具生成 → 逻辑测试（有效链、多链选择、permitted/excluded
名称约束、pathLen、过期/未生效、cA=false 签发、keyCertSign 缺失、叶 cA=true、
未知关键扩展、v1 拒绝、SAN 不匹配、缺中间证书、错锚、篡改签名、循环签发、
DER/Base64 截断、超过 7 张等）→ 页面构建 → 内置服务器 HTTP 冒烟（健康、页面、
模块图、示例数据、路径穿越拦截）→ 内置示例端到端通过 + excluded 域名被拒。
全部通过退出码为 0，否则非 0。

## 安全边界说明

- 信任锚按粘贴即信任处理：锚自身仍做 v3/P-256/SHA-256 配置、有效期与 cA=true 检查，
  但其自签名不作为信任条件（信任来源是离线交付本身）。
- 名称约束仅实现 **dNSName** 部分；含其它 GeneralName 类型的约束会在页面标注，
  不影响 DNS 场景判定（本工具的目标是主机名验证）。
- 吊销（CRL/OCSP）在离线场景不适用，故不纳入。
