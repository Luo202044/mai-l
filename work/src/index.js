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
  // 1. 接收邮件入口
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

  // 2. Web 后台管理入口
  async fetch(request, env, ctx) {
    await ensureTables(env);
    const url = new URL(request.url);
    const path = url.pathname;
    
    const PASSWORD_RAW = env.PASSWORD || 'admin123';
    const SECRET_KEY = env.SECRET_KEY || 'your-secret-key-change-me';

    const getPasswordList = () => {
      return PASSWORD_RAW.split(',').map(p => p.trim()).filter(Boolean);
    };

    const getPwdHash = async (pwd) => {
      const encoder = new TextEncoder();
      const data = encoder.encode(pwd);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    };

    const generateToken = async (timestamp, pwdHash) => {
      const encoder = new TextEncoder();
      const secretKeyData = encoder.encode(SECRET_KEY);
      const key = await crypto.subtle.importKey(
        'raw', secretKeyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
      );
      const messageData = encoder.encode(`${timestamp}:${pwdHash}`);
      const mac = await crypto.subtle.sign('HMAC', key, messageData);
      const hashArray = Array.from(new Uint8Array(mac));
      const hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      return `${timestamp}.${pwdHash}.${hash}`;
    };

    const checkAuth = async (req) => {
      const cookies = parseCookies(req.headers.get('Cookie') || '');
      if (!cookies.auth_token) return false;
      
      const parts = cookies.auth_token.split('.');
      if (parts.length !== 3) return false;
      
      const [timestampStr, tokenPwdHash, hash] = parts;
      const timestamp = parseInt(timestampStr, 10);
      
      if (isNaN(timestamp) || Date.now() - timestamp > 86400000) return false;
      
      const expectedToken = await generateToken(timestamp, tokenPwdHash);
      if (cookies.auth_token !== expectedToken) return false;

      const currentPasswords = getPasswordList();
      const validHashes = await Promise.all(currentPasswords.map(p => getPwdHash(p)));
      return validHashes.includes(tokenPwdHash);
    };

    const parseCookies = (cookieHeader) => {
      const cookies = {};
      if (cookieHeader) {
        cookieHeader.split(';').forEach(cookie => {
          const [name, value] = cookie.trim().split('=');
          if (name && value) cookies[name] = decodeURIComponent(value);
        });
      }
      return cookies;
    };

    // 路由分发
    if (path === '/login' && request.method === 'GET') {
      return new Response(generateLoginPage(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    if (path === '/login' && request.method === 'POST') {
      try {
        const formData = await request.formData();
        const inputPassword = formData.get('password') || '';
        const currentPasswords = getPasswordList();
        
        if (currentPasswords.includes(inputPassword)) {
          const pwdHash = await getPwdHash(inputPassword);
          const token = await generateToken(Date.now(), pwdHash);
          return new Response(null, {
            status: 302,
            headers: {
              'Location': '/',
              'Set-Cookie': `auth_token=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`
            }
          });
        } else {
          return new Response(generateLoginPage('密码错误，请重试'), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
        }
      } catch (error) {
        return new Response(generateLoginPage('登录失败: ' + error.message), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }
    }

    if (path === '/' || path === '') {
      if (!(await checkAuth(request))) {
        return new Response(null, { status: 302, headers: { 'Location': '/login' } });
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

    if (path.startsWith('/view/')) {
      if (!(await checkAuth(request))) {
        return new Response(null, { status: 302, headers: { 'Location': '/login' } });
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

    if (path.startsWith('/raw-html/')) {
      if (!(await checkAuth(request))) return new Response('Unauthorized', { status: 401 });
      const messageId = path.split('/')[2];
      const message = await env.DB.prepare('SELECT html_content, content FROM messages WHERE id = ?').bind(messageId).first();
      if (!message) return new Response('Not Found', { status: 404 });
      
      const body = message.html_content || `<pre style="white-space: pre-wrap; font-family: monospace; padding:10px;">${escapeHtml(message.content)}</pre>`;
      return new Response(body, {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Security-Policy': "default-src 'self' http: https: data: 'unsafe-inline'; script-src 'none'; object-src 'none';" 
        }
      });
    }

    if (path.startsWith('/delete/')) {
      if (!(await checkAuth(request))) return new Response(null, { status: 302, headers: { 'Location': '/login' } });
      const messageId = path.split('/')[2];
      try {
        await env.DB.prepare('DELETE FROM messages WHERE id = ?').bind(messageId).run();
        return new Response('邮件已删除', { status: 200 });
      } catch (error) {
        return new Response('删除失败: ' + error.message, { status: 500 });
      }
    }

    if (path === '/logout') {
      return new Response(null, {
        status: 302,
        headers: { 'Location': '/login', 'Set-Cookie': 'auth_token=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0' }
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
  } catch (err) {
    console.error('❌ 自动建表失败:', err);
  }
}

function escapeHtml(unsafe) {
  if (!unsafe) return '';
  return unsafe.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}

// --- 💡 完美多端兼容的 HTML 模板区域 ---

function generateLoginPage(errorMessage = '') {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no"><title>📧 登录</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; padding: 16px; color: #f8fafc; }
    .login-container { background: #1e293b; border: 1px solid #334155; border-radius: 16px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.4); width: 100%; max-width: 380px; padding: 32px 24px; }
    .login-header { text-align: center; margin-bottom: 24px; }
    .login-header h2 { font-size: 22px; margin-top: 8px; color: #f1f5f9; }
    .login-header p { color: #94a3b8; font-size: 13px; margin-top: 4px; }
    .form-group { margin-bottom: 20px; }
    .form-group label { display: block; margin-bottom: 8px; color: #cbd5e1; font-weight: 500; font-size: 14px; }
    .form-group input { width: 100%; padding: 14px; background: #0f172a; border: 1px solid #334155; border-radius: 8px; font-size: 15px; color: #fff; appearance: none; transition: border-color 0.2s; }
    .form-group input:focus { outline: none; border-color: #3b82f6; }
    .submit-btn { width: 100%; padding: 14px; background: #3b82f6; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: background 0.2s; -webkit-tap-highlight-color: transparent; }
    .submit-btn:hover { background: #2563eb; }
    .error-message { color: #ef4444; font-size: 13px; margin-bottom: 16px; padding: 10px; background-color: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.15); border-radius: 8px; }
  </style>
  </head>
  <body>
    <div class="login-container">
      <div class="login-header"><h1>📧</h1><h2>邮件收件箱</h2><p>请输入密码以继续</p></div>
      <form method="POST" action="/login">
        ${errorMessage ? `<div class="error-message">${escapeHtml(errorMessage)}</div>` : ''}
        <div class="form-group">
          <label for="password">安全密码</label>
          <input type="password" id="password" name="password" required autofocus placeholder="••••••••">
        </div>
        <button type="submit" class="submit-btn">验证登录</button>
      </form>
    </div>
  </body></html>`;
}

function generateListPage(messages) {
  const rows = messages.map(msg => `
    <tr class="${msg.is_read ? 'read' : 'unread'}">
      <td data-label="别名收件箱" style="font-weight: 600; color:#0f172a;">${escapeHtml(msg.mailbox_email)}</td>
      <td data-label="发件人" class="truncate">${escapeHtml(msg.from_address)}</td>
      <td data-label="邮件主题"><a class="subject-link" href="/view/${msg.id}">${escapeHtml(msg.subject || '(无主题)')}</a></td>
      <td data-label="到达时间" class="time-col">${new Date(msg.received_at).toLocaleString('zh-CN', {hour12:false})}</td>
      <td data-label="状态"><span class="badge ${msg.is_read ? 'badge-read' : 'badge-unread'}">${msg.is_read ? '已读' : '未读'}</span></td>
      <td data-label="管理"><button class="delete-btn" onclick="deleteEmail(${msg.id}, event)">删除</button></td>
    </tr>
  `).join('');

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>📧 收件箱</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f8fafc; color: #1e293b; padding: 12px; }
    .container { max-width: 1200px; margin: 0 auto; padding-top: 8px; }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; background: white; padding: 16px; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
    .header h1 { font-size: 18px; font-weight: 700; color: #0f172a; }
    .logout-btn { padding: 8px 14px; background: #f1f5f9; color: #64748b; text-decoration: none; border-radius: 6px; font-size: 13px; font-weight: 500; }
    .table-wrapper { background: white; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); overflow: hidden; }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }
    th { background: #f8fafc; padding: 14px 16px; font-weight: 600; color: #64748b; border-bottom: 1px solid #e2e8f0; }
    td { padding: 14px 16px; border-bottom: 1px solid #f1f5f9; color: #334155; }
    tr:hover { background-color: #f8fafc; }
    tr.unread { background-color: #f0fdf4; }
    .subject-link { color: #2563eb; text-decoration: none; font-weight: 500; display: inline-block; word-break: break-all; }
    .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500; }
    .badge-unread { background: #dcfce7; color: #166534; }
    .badge-read { background: #f1f5f9; color: #64748b; }
    .delete-btn { padding: 6px 14px; background: #fff; color: #ef4444; border: 1px solid #fee2e2; border-radius: 6px; cursor: pointer; font-size: 13px; }
    .empty { text-align: center; padding: 40px; color: #94a3b8; }
    .truncate { max-width: 200px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

    /* 📱 核心响应式移动端 CSS 媒体查询 断点 */
    @media (max-width: 768px) {
      .header h1 { font-size: 16px; }
      thead { display: none; } /* 隐藏原生表头 */
      tr { display: block; border-bottom: 8px solid #f1f5f9; padding: 12px 4px; background: #fff; }
      tr.unread { background-color: #fcfdfd; border-left: 4px solid #22c55e; }
      td { display: flex; justify-content: space-between; align-items: center; border-bottom: none; padding: 8px 12px; text-align: right; font-size: 13px; }
      td::before { content: attr(data-label); font-weight: 500; color: #64748b; padding-right: 16px; text-align: left; min-width: 90px; }
      .truncate { max-width: 60%; white-space: normal; overflow: visible; text-overflow: clip; word-break: break-all; }
      .subject-link { text-align: right; max-width: 100%; }
      .delete-btn { width: 100%; text-align: center; padding: 8px; margin-top: 4px; }
    }
  </style>
  <script>
    function deleteEmail(id, e) {
      e.preventDefault();
      if (confirm('确定要彻底删除该邮件吗？')) {
        fetch('/delete/' + id, { method: 'POST' }).then(() => location.reload());
      }
    }
  </script>
  </head>
  <body>
    <div class="container">
      <div class="header"><h1>📬 临时收件箱 (${messages.length})</h1><a href="/logout" class="logout-btn">安全退出</a></div>
      <div class="table-wrapper">
        <table>
          <thead><tr><th>别名收件箱</th><th>发件人</th><th>邮件主题</th><th>到达时间</th><th>状态</th><th>管理</th></tr></thead>
          <tbody>
            ${rows ? rows : '<tr><td colspan="6" class="empty">📭 暂无任何邮件。</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  </body></html>`;
}

function generateDetailPage(message) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>查看邮件</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f8fafc; color: #1e293b; padding: 12px; }
    .container { max-width: 900px; margin: 0 auto; }
    .back-btn { display: inline-flex; align-items: center; padding: 8px 14px; background: white; border: 1px solid #e2e8f0; border-radius: 6px; color: #475569; text-decoration: none; font-size: 13px; margin-bottom: 12px; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }
    .card { background: white; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); padding: 16px; margin-bottom: 16px; }
    .subject { font-size: 18px; font-weight: 700; color: #0f172a; margin-bottom: 16px; line-height: 1.4; word-break: break-all; }
    .meta-grid { display: grid; grid-template-columns: auto 1fr; gap: 8px 12px; font-size: 13px; border-bottom: 1px solid #f1f5f9; padding-bottom: 16px; margin-bottom: 16px; }
    .meta-label { color: #64748b; font-weight: 500; min-width: 50px; }
    .meta-value { color: #334155; word-break: break-all; }
    .iframe-container { width: 100%; border: 1px solid #e2e8f0; border-radius: 8px; background: #fff; overflow-x: auto; -webkit-overflow-scrolling: touch; margin-top: 10px; }
    iframe { width: 100%; min-height: 450px; border: none; display: block; }
    .danger-zone { display: flex; justify-content: flex-end; }
    .delete-btn { width: auto; padding: 10px 20px; background: #fee2e2; color: #ef4444; border: 1px solid #fca5a5; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 14px; }
    
    @media (max-width: 768px) {
      .card { padding: 12px; }
      .subject { font-size: 16px; }
      .danger-zone { justify-content: center; }
      .delete-btn { width: 100%; text-align: center; }
    }
  </style>
  <script>
    function deleteAndGoBack() {
      if (confirm('确定要删除该邮件并返回收件箱吗？')) {
        fetch('/delete/${message.id}', { method: 'POST' }).then(() => { window.location.href = '/'; });
      }
    }
    function resizeIframe(obj) {
      setTimeout(() => {
        try {
          obj.style.height = obj.contentWindow.document.documentElement.scrollHeight + 40 + 'px';
        } catch(e) {
          obj.style.height = '550px';
        }
      }, 250);
    }
  </script>
  </head>
  <body>
    <div class="container">
      <a href="/" class="back-btn">← 返回收件箱</a>
      <div class="card">
        <div class="subject">${escapeHtml(message.subject || '(无主题)')}</div>
        <div class="meta-grid">
          <div class="meta-label">发件人</div><div class="meta-value">${escapeHtml(message.from_address)}</div>
          <div class="meta-label">收件别名</div><div class="meta-value">${escapeHtml(message.mailbox_email)}</div>
          <div class="meta-label">时间</div><div class="meta-value">${new Date(message.received_at).toLocaleString()}</div>
        </div>
        <div class="iframe-container">
          <iframe src="/raw-html/${message.id}" sandbox="allow-popups allow-popups-to-escape-sandbox" onload="resizeIframe(this)"></iframe>
        </div>
      </div>
      <div class="danger-zone">
        <button class="delete-btn" onclick="deleteAndGoBack()">🗑️ 彻底删除邮件</button>
      </div>
    </div>
  </body></html>`;
}
