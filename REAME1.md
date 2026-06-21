# 📧 Cloudflare Mail Worker

一个基于 Cloudflare Workers + D1 的邮件接收与 Web 查看系统。

## 部署步骤

1. 在 Cloudflare Dashboard 中创建 D1 数据库（如果尚未创建），记录 ID。
2. 修改 `wrangler.toml` 中的 `database_id` 和 `database_name`。
3. 安装依赖：`npm install`
4. 初始化数据库表：`npx wrangler d1 execute <数据库名> --file=./schema.sql`
5. 设置登录密码：`npx wrangler secret put PASSWORD`（用户名固定为 `admin`）
6. 部署 Worker：`npm run deploy`

## 配置邮件路由

在 Cloudflare Dashboard → Email → Email Routing 中添加规则，将邮件发送到该 Worker。

## 访问

部署后会得到一个 `*.workers.dev` 域名，打开后输入用户名 `admin` 和你设置的密码即可查看邮件。
