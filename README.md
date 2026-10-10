# Cloud Space

基于 **Cloudflare Workers + R2** 的单文件私有云盘。前端界面、REST API、分享页全部塞在一个 `index.js` 里，没有构建步骤，不需要数据库。

## 特性

- **文件管理** — 上传、下载、重命名、移动、删除，带回收站（软删除可还原）
- **文件夹** — 支持整目录递归上传（拖拽文件夹或点「选择文件夹」），移动/重命名会连带子目录
- **分享链接** — 可设访问密码、有效期、访问次数上限，随时撤销
- **在线预览** — 图片/视频灯箱预览，文本与 Markdown 在线编辑（带预览模式）
- **存储概览** — 已用空间与文件数量统计

## 部署（连接 GitHub，自动创建 R2）

> **先决条件**：账号必须已开通 R2。去控制台 R2 页面点一次同意条款，否则自动创建 bucket 会失败——这是最常见的部署失败原因。

1. 把本目录推送到 GitHub 仓库
2. Cloudflare 控制台 → **Workers & Pages** → **Create** → **Workers** → **Connect to Git**，选择仓库
3. 填写构建配置：

   | 配置项 | 值 |
   | --- | --- |
   | Project name | `r2-file-manager`（**必须与 `wrangler.jsonc` 的 `name` 完全一致**） |
   | Build command | `npm install` |
   | Deploy command | `npx wrangler deploy` |

4. 部署完成后访问分配的域名，首次会进入**初始化页面**，设置管理员账号密码即可开始使用

### 自动创建 R2 的原理

`wrangler.jsonc` 里的 R2 绑定**故意不写 `bucket_name`**：

```jsonc
"r2_buckets": [
  { "binding": "MY_BUCKET" }   // 不写 bucket_name → 部署时自动创建并绑定
]
```

部署时 Cloudflare 会自动创建一个以 Worker 名称为前缀的 bucket，并绑定到 `env.MY_BUCKET`。写成 `{ "binding": "MY_BUCKET", "bucket_name": "xxx" }` 就变成手动指定，**不会**自动创建。

### ⚠️ 两个必须知道的坑

1. **R2 未开通 → 自动创建必失败**（见上方先决条件）。
2. **通过控制台构建部署时，bucket ID 不会写回你的仓库**，只能在控制台里查看。所以之后如果改成本地 `wrangler deploy`，它会当成「无 ID」**再创建一个空 bucket**，看起来像线上数据全丢了。真要在本地部署前，先从控制台复制桶名补进配置：
   ```jsonc
   "r2_buckets": [{ "binding": "MY_BUCKET", "bucket_name": "<从控制台复制>" }]
   ```

## 本地开发

```bash
npm install
npm run dev      # 本地启动，wrangler 会自动创建本地 R2（存在 .wrangler/，不碰线上）
npm run check    # dry-run，只验证配置与打包，不部署
npm run deploy   # 部署到线上
```

`npm run check` 输出里出现下面这行即表示绑定配置正确：

```
Binding               Resource
env.MY_BUCKET         R2 Bucket
```

## 配置项

`wrangler.jsonc`：

| 字段 | 说明 |
| --- | --- |
| `name` | Worker 名称，自动创建的资源以此为前缀 |
| `main` | 入口文件，默认 `index.js` |
| `compatibility_date` | 运行时兼容日期，不能晚于今天 |
| `observability` | 开启线上日志 |
| `upload_source_maps` | 让日志里的异常堆栈映射回源码真实行号 |
| `r2_buckets` | R2 绑定，见上文 |

本项目**不需要任何环境变量或 Secret** —— 管理员凭据在首次访问时设置，加密后存在 R2 里。

## 数据存储

所有数据都在 R2 桶内，`.sys_` 前缀为系统保留，不会出现在文件列表中：

| Key | 用途 |
| --- | --- |
| `.sys_config.json` | 管理员账号与加盐口令哈希 |
| `.sys_shares.json` | 分享记录（token / 密码 / 有效期 / 访问计数） |
| `.sys_uploads.json` | 上传历史（上限 200 条） |
| `.sys_sessions.json` | 登录会话（7 天有效期） |
| `.sys_trash/*` | 回收站 |
| 其余任意 key | 用户文件与文件夹 |

## 接口一览

| 路径 | 说明 |
| --- | --- |
| `/` | 管理界面 |
| `/s/<token>` | 分享页（免登录，支持 `?pwd=` 与 `?mode=inline\|download`） |
| `/file/<key>` | 鉴权后取文件，支持 Range 与 ETag |
| `/api/*` | 24 个业务接口（鉴权、文件、分享、回收站、设置） |

## 安全说明

- 口令使用 **SHA-256 + 随机盐**，比对采用恒定时间算法
- 会话是服务端随机 token，Cookie 带 `HttpOnly` + `SameSite=Strict` + `Secure`，登出即吊销
- 登录按 IP 限流：5 次失败锁定 10 分钟
- 分享页、错误页、密码页全部做 HTML 转义
- 上传的 HTML / SVG / JS 等可执行类型强制以附件下载，避免同源脚本执行
- API 响应统一 `Cache-Control: no-store`

> 提示：控制台构建不会把资源 ID 写回仓库，因此**仓库里的 `wrangler.jsonc` 始终保持不带 `bucket_name` 的状态**，这样每次重新部署都会复用同一个自动创建的资源。

## 技术栈

Cloudflare Workers · R2 · Vue 3（CDN）· Tailwind CSS（CDN）· marked
