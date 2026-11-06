# new-api — 子比(Zibll)代理登录版

基于 [QuantumNous/new-api](https://github.com/QuantumNous/new-api)（上游 `2de51a19`），
原生接入**子比主题代理登录协议**：把 new-api 作为「代理登录客户端」，用户通过你的
子比主站完成真实的微信/QQ 等社交登录，md5 签名回传身份后自动在本站登录/注册/绑定。

> 分支/仓库说明：本仓库 `.github/workflows/` 为空（推送端 token 权限限制），
> 如需 GitHub Actions 云构建，执行
> `cp docs/zibll-build.workflow.yml .github/workflows/zibll-build.yml` 后提交即可。

## 支持的登录方式（14 种，管理后台多选启用）

微信（weixin 扫码）、微信公众号（weixingzh，扫码轮询 + 验证码）、QQ、微博、抖音、
百度、支付宝、Gitee、GitHub、Google、Microsoft、Facebook、Twitter、Apple。

国内渠道显示名为中文；产品名本身是字母的（QQ / Gitee / GitHub / Google 等）保持原样。

另有 **Google One Tap**（原生通道，不走代理）：设置选项
`GoogleOneTapClientID` 后，登录页出现 Google 按钮与 One Tap 提示，
凭证经 RS256 + Google JWKS 校验后以 `google_id` 登录/注册。

## 快速开始

### 1. 子比主站（服务端）

主题设置 → 社交/用户 → 「Zibll代理登录」选择 **代理登录服务端**，
复制生成的**通讯密钥**；并确保要代理的社交登录（如微信）已在主站配置完成。

### 2. new-api（客户端，本仓库）

**方式 A：Docker 本地构建（推荐）**

```bash
docker build -t new-api-zibll .
docker run -d --name new-api -p 3000:3000 -v /home/data/new-api:/data new-api-zibll
```

**方式 B：GitHub Actions 云构建**

```bash
cp docs/zibll-build.workflow.yml .github/workflows/zibll-build.yml
git add . && git commit -m "ci: add zibll build workflow" && git push
# GitHub 仓库 → Actions → "Zibll agent login build" → Run workflow
# 完成后在 run 页面下载 artifact new-api-zibll-image.tar.gz
#   docker load -i new-api-zibll-image.tar.gz   # 得到镜像 new-api-zibll:ci
```

**方式 C：源码直跑**

```bash
# 前端
cd web && bun install && bun run build && cd ..
# 后端（产物内嵌 web/dist）
CGO_ENABLED=0 go build -o new-api .
./new-api --port 3000 --data /home/data/new-api
```

### 3. 配置代理登录

系统设置 → 登录认证 → **子比代理登录**：

- 主站地址：`https://你的子比站/`
- 通讯密钥：主站后台复制
- 登录方式：勾选要启用的方式（主站须已开启对应的社交登录）

保存后登录页立即出现对应按钮；个人中心「安全与访问」中可绑定/解绑。

### 4.（可选）Google One Tap

```bash
curl -X PUT https://你的new-api/api/option/ \
  -H "Authorization: Bearer <root访问令牌>" -H 'Content-Type: application/json' \
  -d '{"key":"GoogleOneTapClientID","value":"xxxx.apps.googleusercontent.com"}'
```

client id 在 Google Cloud Console → OAuth 客户端（Web 应用）创建，授权来源填本站域名。

## 协议实现说明

- 签名与子比主题 `oauth/sdk/agent.php` 逐字节兼容：
  `md5(按查询串顺序拼接参数值（嵌套数组折叠为 "Array"）+ 通讯密钥)`；
  单元测试用 PHP 8.3 生成的黄金值对照（`oauth/zibll_test.go`）。
- 公众号流程完整实现扫码轮询（`check_callback`）与验证码登录（`code_check`）。
- 绑定复用 new-api 自定义 OAuth 体系（`custom_oauth_providers` 表
  `provider_kind=zibll` 托管行 + `user_oauth_bindings`），停用方式不丢绑定。
- 安全：回调强制验签（constant-time 比较）+ AuthFlow state（防 CSRF/重放）+
  CriticalRateLimit；通讯密钥只入库不回显。

## License

同上游 new-api：AGPL-3.0（见 LICENSE）。附加代码遵循相同协议。
