import PostalMime from 'postal-mime';

const CREATE_TABLES_SQL = `
CREATE TABLE IF NOT EXISTS mailboxes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox_id INTEGER NOT NULL,
    from_address TEXT NOT NULL,
    subject TEXT,
    content TEXT,
    html_content TEXT,
    received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_read BOOLEAN DEFAULT 0,
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_id ON messages(mailbox_id);
CREATE INDEX IF NOT EXISTS idx_messages_received_at ON messages(received_at);
`;

let tablesReady = false;

export default {
  async email(message, env, ctx) {
    await ensureTables(env);
    const toAddress = message.to;
    if (!toAddress) return;
    try {
      const parser = new PostalMime();
      const parsedEmail = await parser.parse(message.raw);
      let mailbox = await env.DB.prepare('SELECT id FROM mailboxes WHERE email = ?').bind(toAddress).first();
      if (!mailbox) {
        const result = await env.DB.prepare('INSERT INTO mailboxes (email) VALUES (?)').bind(toAddress).run();
        mailbox = { id: result.meta.last_row_id };
      }
      await env.DB.prepare(
        `INSERT INTO messages (mailbox_id, from_address, subject, content, html_content)
         VALUES (?, ?, ?, ?, ?)`
      ).bind(mailbox.id, parsedEmail.from?.address || 'Unknown', parsedEmail.subject || '(无主题)',
        parsedEmail.text || parsedEmail.html || '(无内容)', parsedEmail.html || null).run();
      console.log(`✅ 邮件已存储: ${toAddress} 来自 ${parsedEmail.from?.address}`);
    } catch (error) {
      console.error('❌ 处理邮件失败:', error);
    }
  },

  async fetch(request, env, ctx) {
    await ensureTables(env);
    const url = new URL(request.url);
    const path = url.pathname;
    const PASSWORD = env.PASSWORD || 'admin123';
    const SECRET_KEY = env.SECRET_KEY || 'your-secret-key-change-me';

    // 生成会话令牌
    const generateToken = async (password) => {
      const encoder = new TextEncoder();
      const data = encoder.encode(`${password}:${Date.now()}:${SECRET_KEY}`);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    };

    // 检查认证 Cookie
    const checkAuth = (req) => {
      const cookies = parseCookies(req.headers.get('Cookie') || '');
      return cookies.auth_token ? true : false;
    };

    // 解析 Cookie
    const parseCookies = (cookieHeader) => {
      const cookies = {};
      if (cookieHeader) {
        cookieHeader.split(';').forEach(cookie => {
          const [name, value] = cookie.trim().split('=');
          if (name && value) {
            cookies[name] = decodeURIComponent(value);
          }
        });
      }
      return cookies;
    };

    // 登录页面
    if (path === '/login' && request.method === 'GET') {
      return new Response(generateLoginPage(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    // 处理登录提交
    if (path === '/login' && request.method === 'POST') {
      try {
        const formData = await request.formData();
        const password = formData.get('password');
        
        if (password === PASSWORD) {
          const token = await generateToken(password);
          const response = new Response(null, {
            status: 302,
            headers: {
              'Location': '/',
              'Set-Cookie': `auth_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400`
            }
          });
          return response;
        } else {
          return new Response(generateLoginPage('密码错误，请重试'), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
        }
      } catch (error) {
        return new Response(generateLoginPage('登录失败: ' + error.message), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }
    }

    // 邮件列表
    if (path === '/' || path === '') {
      if (!checkAuth(request)) {
        return new Response(null, {
          status: 302,
          headers: { 'Location': '/login' }
        });
      }
      try {
        const messages = await env.DB.prepare(
          `SELECT m.*, mb.email as mailbox_email FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id ORDER BY m.received_at DESC`
        ).all();
        return new Response(generateListPage(messages.results), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      } catch (error) {
        return new Response('加载邮件列表失败: ' + error.message, { status: 500 });
      }
    }

    // 查看邮件详情
    if (path.startsWith('/view/')) {
      if (!checkAuth(request)) {
        return new Response(null, {
          status: 302,
          headers: { 'Location': '/login' }
        });
      }
      const messageId = path.split('/')[2];
      if (!messageId) return new Response('缺少邮件ID', { status: 400 });
      try {
        const message = await env.DB.prepare(
          `SELECT m.*, mb.email as mailbox_email FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id WHERE m.id = ?`
        ).bind(messageId).first();
        if (!message) return new Response('邮件未找到', { status: 404 });
        await env.DB.prepare('UPDATE messages SET is_read = 1 WHERE id = ?').bind(messageId).run();
        return new Response(generateDetailPage(message), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      } catch (error) {
        return new Response('加载邮件详情失败: ' + error.message, { status: 500 });
      }
    }

    // 删除邮件
    if (path.startsWith('/delete/') && request.method === 'POST') {
      if (!checkAuth(request)) {
        return new Response(null, {
          status: 302,
          headers: { 'Location': '/login' }
        });
      }
      const messageId = path.split('/')[2];
      if (!messageId) return new Response('缺少邮件ID', { status: 400 });
      try {
        await env.DB.prepare('DELETE FROM messages WHERE id = ?').bind(messageId).run();
        return new Response('邮件已删除', { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
      } catch (error) {
        return new Response('删除邮件失败: ' + error.message, { status: 500 });
      }
    }

    // 登出
    if (path === '/logout') {
      return new Response(null, {
        status: 302,
        headers: {
          'Location': '/login',
          'Set-Cookie': 'auth_token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'
        }
      });
    }

    return new Response('Not Found', { status: 404 });
  }
};

async function ensureTables(env) {
  if (tablesReady) return;
  try {
    await env.DB.exec(CREATE_TABLES_SQL);
    tablesReady = true;
    console.log('✅ 数据库表已自动创建');
  } catch (err) {
    console.error('❌ 自动建表失败:', err);
  }
}

function generateLoginPage(errorMessage = '') {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>📧 邮件收件箱 - 登录</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      padding: 20px;
    }
    .login-container {
      background: white;
      border-radius: 10px;
      box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
      width: 100%;
      max-width: 400px;
      padding: 40px;
    }
    .login-header {
      text-align: center;
      margin-bottom: 30px;
    }
    .login-header h1 {
      font-size: 32px;
      margin-bottom: 10px;
    }
    .login-header p {
      color: #666;
      font-size: 14px;
    }
    .form-group {
      margin-bottom: 20px;
    }
    .form-group label {
      display: block;
      margin-bottom: 8px;
      color: #333;
      font-weight: 500;
      font-size: 14px;
    }
    .form-group input {
      width: 100%;
      padding: 12px;
      border: 1px solid #ddd;
      border-radius: 5px;
      font-size: 14px;
      transition: border-color 0.3s;
    }
    .form-group input:focus {
      outline: none;
      border-color: #667eea;
      box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }
    .submit-btn {
      width: 100%;
      padding: 12px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      border-radius: 5px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .submit-btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
    }
    .submit-btn:active {
      transform: translateY(0);
    }
    .error-message {
      color: #dc3545;
      font-size: 14px;
      margin-bottom: 20px;
      padding: 10px;
      background-color: #f8d7da;
      border: 1px solid #f5c6cb;
      border-radius: 5px;
      display: ${errorMessage ? 'block' : 'none'};
    }
  </style>
  </head>
  <body>
    <div class="login-container">
      <div class="login-header">
        <h1>📧</h1>
        <h2>邮件收件箱</h2>
        <p>请输入密码登录</p>
      </div>
      <form method="POST" action="/login">
        ${errorMessage ? `<div class="error-message">${escapeHtml(errorMessage)}</div>` : ''}
        <div class="form-group">
          <label for="password">密码</label>
          <input type="password" id="password" name="password" required autofocus placeholder="输入密码">
        </div>
        <button type="submit" class="submit-btn">登录</button>
      </form>
    </div>
  </body>
  </html>`;
}

function generateListPage(messages) {
  const rows = messages.map(msg => `
    <tr>
      <td>${escapeHtml(msg.mailbox_email)}</td>
      <td>${escapeHtml(msg.from_address)}</td>
      <td><a href="/view/${msg.id}">${escapeHtml(msg.subject)}</a></td>
      <td>${new Date(msg.received_at).toLocaleString()}</td>
      <td>${msg.is_read ? '已读' : '未读'}</td>
      <td><button class="delete-btn" onclick="deleteEmail(${msg.id})">删除</button></td>
    </tr>
  `).join('');
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>📧 邮件收件箱</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background-color: #f5f5f5;
      max-width: 1200px;
      margin: 0 auto;
      padding: 20px;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 30px;
      background: white;
      padding: 20px;
      border-radius: 8px;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
    }
    .header h1 {
      font-size: 24px;
      margin: 0;
    }
    .logout-btn {
      padding: 10px 20px;
      background: #dc3545;
      color: white;
      text-decoration: none;
      border-radius: 5px;
      font-weight: 600;
      transition: background 0.3s;
    }
    .logout-btn:hover {
      background: #c82333;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      background: white;
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
    }
    th {
      background: #f8f9fa;
      padding: 15px;
      text-align: left;
      font-weight: 600;
      border-bottom: 2px solid #e9ecef;
    }
    td {
      padding: 15px;
      border-bottom: 1px solid #e9ecef;
    }
    tr:last-child td {
      border-bottom: none;
    }
    a {
      color: #667eea;
      text-decoration: none;
    }
    a:hover {
      text-decoration: underline;
    }
    .delete-btn {
      padding: 6px 12px;
      background: #ff6b6b;
      color: white;
      border: none;
      border-radius: 3px;
      cursor: pointer;
      font-size: 12px;
      transition: background 0.3s;
    }
    .delete-btn:hover {
      background: #ee5a52;
    }
    .empty-message {
      text-align: center;
      padding: 40px;
      color: #999;
    }
  </style>
  <script>
    function deleteEmail(id) {
      if (confirm('确定要删除该邮件吗？')) {
        fetch('/delete/' + id, { method: 'POST' }).then(() => location.reload());
      }
    }
  </script>
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
          <th>操作</th>
        </tr>
      </thead>
      <tbody>
        ${rows ? rows : '<tr><td colspan="6" class="empty-message">暂无邮件</td></tr>'}
      </tbody>
    </table>
  </body>
  </html>`;
}

function generateDetailPage(message) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>📄 ${escapeHtml(message.subject)}</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background-color: #f5f5f5;
      max-width: 800px;
      margin: 0 auto;
      padding: 20px;
    }
    .back-link {
      display: inline-block;
      margin-bottom: 20px;
      color: #667eea;
      text-decoration: none;
      font-weight: 600;
    }
    .back-link:hover {
      text-decoration: underline;
    }
    h1 {
      margin-bottom: 20px;
      color: #333;
    }
    .email-meta {
      background: white;
      padding: 20px;
      border-radius: 8px;
      margin-bottom: 20px;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
    }
    .email-meta p {
      margin-bottom: 10px;
      color: #555;
    }
    .email-meta strong {
      color: #333;
    }
    .email-content {
      background: white;
      padding: 20px;
      border-radius: 8px;
      margin-bottom: 20px;
      white-space: pre-wrap;
      word-wrap: break-word;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
      line-height: 1.6;
    }
    .email-content img {
      max-width: 100%;
      height: auto;
    }
    .actions {
      display: flex;
      gap: 10px;
    }
    .delete-btn {
      padding: 12px 20px;
      background: #dc3545;
      color: white;
      border: none;
      border-radius: 5px;
      cursor: pointer;
      font-weight: 600;
      transition: background 0.3s;
    }
    .delete-btn:hover {
      background: #c82333;
    }
  </style>
  <script>
    function deleteAndGoBack() {
      if (confirm('确定要删除该邮件吗？')) {
        fetch('/delete/${message.id}', { method: 'POST' }).then(() => {
          window.location.href = '/';
        });
      }
    }
  </script>
  </head>
  <body>
    <a href="/" class="back-link">← 返回收件箱</a>
    <h1>${escapeHtml(message.subject)}</h1>
    <div class="email-meta">
      <p><strong>发件人:</strong> ${escapeHtml(message.from_address)}</p>
      <p><strong>收件人:</strong> ${escapeHtml(message.mailbox_email)}</p>
      <p><strong>接收时间:</strong> ${new Date(message.received_at).toLocaleString()}</p>
    </div>
    <div class="email-content">${message.html_content ? message.html_content : escapeHtml(message.content || '(无内容)')}</div>
    <div class="actions">
      <button class="delete-btn" onclick="deleteAndGoBack()">🗑️ 删除邮件</button>
    </div>
  </body>
  </html>`;
}

function escapeHtml(unsafe) {
  if (!unsafe) return '';
  return unsafe.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}
