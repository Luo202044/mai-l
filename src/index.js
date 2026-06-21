// src/index.js
import { PostalMime } from 'postal-mime';

/**
 * Cloudflare Worker 接收邮件并存储至 D1，同时提供 Web 界面查看邮件
 * 环境变量（通过 wrangler secret 设置）：
 *   - PASSWORD: 登录密码（用户名固定为 admin）
 *   - DB: D1 数据库绑定（在 wrangler.toml 中配置）
 */
export default {
    // ---------- 邮件接收处理器 ----------
    async email(message, env, ctx) {
        const toAddress = message.to;
        if (!toAddress) return; // 无收件人则忽略

        try {
            // 解析邮件原始内容
            const parser = new PostalMime();
            const parsedEmail = await parser.parse(message.raw);

            // 1. 查找或创建邮箱账号
            let mailbox = await env.DB.prepare(
                'SELECT id FROM mailboxes WHERE email = ?'
            ).bind(toAddress).first();

            if (!mailbox) {
                const result = await env.DB.prepare(
                    'INSERT INTO mailboxes (email) VALUES (?)'
                ).bind(toAddress).run();
                mailbox = { id: result.meta.last_row_id };
            }

            // 2. 存储邮件
            await env.DB.prepare(
                `INSERT INTO messages 
                 (mailbox_id, from_address, subject, content, html_content)
                 VALUES (?, ?, ?, ?, ?)`
            ).bind(
                mailbox.id,
                parsedEmail.from?.address || 'Unknown',
                parsedEmail.subject || '(无主题)',
                parsedEmail.text || parsedEmail.html || '(无内容)',
                parsedEmail.html || null
            ).run();

            console.log(`✅ 邮件已存储: ${toAddress} 来自 ${parsedEmail.from?.address}`);
        } catch (error) {
            console.error('❌ 处理邮件失败:', error);
            // 可选择重新抛出以触发重试
        }
    },

    // ---------- HTTP 请求处理器（Web 界面） ----------
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;

        // 从环境变量获取密码（必须通过 wrangler secret 设置）
        const BASIC_PASS = env.PASSWORD || 'admin123';

        // ---------- 认证辅助函数 ----------
        const requireAuth = () => {
            return new Response('需要登录', {
                status: 401,
                headers: {
                    'WWW-Authenticate': 'Basic realm="Mail Reader", charset="UTF-8"'
                }
            });
        };

        const checkAuth = (request) => {
            const authHeader = request.headers.get('Authorization');
            if (!authHeader) return false;

            const [scheme, encoded] = authHeader.split(' ');
            if (scheme !== 'Basic' || !encoded) return false;

            const credentials = Buffer.from(encoded, 'base64').toString();
            const [user, pass] = credentials.split(':');
            return user === 'admin' && pass === BASIC_PASS;
        };

        // ---------- 路由 ----------

        // 1. 根路径 - 邮件列表
        if (path === '/' || path === '') {
            if (!checkAuth(request)) return requireAuth();

            try {
                const messages = await env.DB.prepare(
                    `SELECT m.*, mb.email as mailbox_email
                     FROM messages m
                     JOIN mailboxes mb ON m.mailbox_id = mb.id
                     ORDER BY m.received_at DESC`
                ).all();

                return new Response(generateListPage(messages.results), {
                    headers: { 'Content-Type': 'text/html; charset=utf-8' }
                });
            } catch (error) {
                console.error('查询邮件失败:', error);
                return new Response('加载邮件列表失败', { status: 500 });
            }
        }

        // 2. /view/:id - 邮件详情
        if (path.startsWith('/view/')) {
            if (!checkAuth(request)) return requireAuth();

            const messageId = path.split('/')[2];
            if (!messageId) {
                return new Response('缺少邮件ID', { status: 400 });
            }

            try {
                const message = await env.DB.prepare(
                    `SELECT m.*, mb.email as mailbox_email
                     FROM messages m
                     JOIN mailboxes mb ON m.mailbox_id = mb.id
                     WHERE m.id = ?`
                ).bind(messageId).first();

                if (!message) {
                    return new Response('邮件未找到', { status: 404 });
                }

                // 标记为已读
                await env.DB.prepare(
                    'UPDATE messages SET is_read = 1 WHERE id = ?'
                ).bind(messageId).run();

                return new Response(generateDetailPage(message), {
                    headers: { 'Content-Type': 'text/html; charset=utf-8' }
                });
            } catch (error) {
                console.error('查看邮件失败:', error);
                return new Response('加载邮件详情失败', { status: 500 });
            }
        }

        // 3. /logout - 退出（实际是触发重新认证）
        if (path === '/logout') {
            return new Response('已退出', {
                status: 401,
                headers: {
                    'WWW-Authenticate': 'Basic realm="Mail Reader", charset="UTF-8"'
                }
            });
        }

        // 4. 其他路径 - 404
        return new Response('Not Found', { status: 404 });
    }
};

// ---------- HTML 页面生成函数 ----------

function generateListPage(messages) {
    const rows = messages.map(msg => `
        <tr>
            <td>${escapeHtml(msg.mailbox_email)}</td>
            <td>${escapeHtml(msg.from_address)}</td>
            <td><a href="/view/${msg.id}">${escapeHtml(msg.subject)}</a></td>
            <td>${new Date(msg.received_at).toLocaleString()}</td>
            <td>${msg.is_read ? '已读' : '未读'}</td>
        </tr>
    `).join('');

    return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>📧 邮件收件箱</title>
    <style>
        body { font-family: sans-serif; max-width: 1200px; margin: 20px auto; padding: 0 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .header { display: flex; justify-content: space-between; align-items: center; }
        .logout-btn { padding: 8px 16px; background: #dc3545; color: white; text-decoration: none; border-radius: 4px; }
        .logout-btn:hover { background: #c82333; }
    </style>
</head>
<body>
    <div class="header">
        <h1>📬 邮件收件箱 (${messages.length} 封)</h1>
        <a href="/logout" class="logout-btn">退出登录</a>
    </div>
    <table>
        <thead>
            <tr>
                <th>收件人</th>
                <th>发件人</th>
                <th>主题</th>
                <th>接收时间</th>
                <th>状态</th>
            </tr>
        </thead>
        <tbody>
            ${rows || '<tr><td colspan="5">暂无邮件</td></tr>'}
        </tbody>
    </table>
</body>
</html>
    `;
}

function generateDetailPage(message) {
    return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>📄 ${escapeHtml(message.subject)}</title>
    <style>
        body { font-family: sans-serif; max-width: 800px; margin: 20px auto; padding: 0 20px; }
        .back-link { display: inline-block; margin-bottom: 20px; }
        .email-meta { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
        .email-content { white-space: pre-wrap; word-wrap: break-word; }
        .email-content img { max-width: 100%; }
    </style>
</head>
<body>
    <a href="/" class="back-link">← 返回收件箱</a>
    <h1>${escapeHtml(message.subject)}</h1>
    <div class="email-meta">
        <p><strong>发件人:</strong> ${escapeHtml(message.from_address)}</p>
        <p><strong>收件人:</strong> ${escapeHtml(message.mailbox_email)}</p>
        <p><strong>接收时间:</strong> ${new Date(message.received_at).toLocaleString()}</p>
    </div>
    <div class="email-content">
        ${message.html_content ? message.html_content : escapeHtml(message.content || '(无内容)')}
    </div>
</body>
</html>
    `;
}

/**
 * 简单的 HTML 转义，防止 XSS
 */
function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
