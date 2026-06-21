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
    const BASIC_PASS = env.PASSWORD || 'admin123';

    const requireAuth = () => new Response('需要登录', { status: 401, headers: { 'WWW-Authenticate': 'Basic realm="Mail Reader", charset="UTF-8"' } });
    const checkAuth = (req) => {
      const authHeader = req.headers.get('Authorization');
      if (!authHeader) return false;
      const [scheme, encoded] = authHeader.split(' ');
      if (scheme !== 'Basic' || !encoded) return false;
      const credentials = atob(encoded);
      const [user, pass] = credentials.split(':');
      return user === 'admin' && pass === BASIC_PASS;
    };

    if (path === '/' || path === '') {
      if (!checkAuth(request)) return requireAuth();
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
      if (!checkAuth(request)) return requireAuth();
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
    if (path.startsWith('/delete/') && request.method === 'POST') {
      if (!checkAuth(request)) return requireAuth();
      const messageId = path.split('/')[2];
      if (!messageId) return new Response('缺少邮件ID', { status: 400 });
      try {
        await env.DB.prepare('DELETE FROM messages WHERE id = ?').bind(messageId).run();
        return new Response('邮件已删除', { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
      } catch (error) {
        return new Response('删除邮件失败: ' + error.message, { status: 500 });
      }
    }
    if (path === '/logout') {
      return new Response('已退出', { status: 401, headers: { 'WWW-Authenticate': 'Basic realm="Mail Reader", charset="UTF-8"' } });
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
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>📧 邮件收件箱</title>
  <style>body{font-family:sans-serif;max-width:1200px;margin:20px auto;padding:0 20px;}
  table{width:100%;border-collapse:collapse;margin-top:20px;}th,td{border:1px solid #ddd;padding:8px;text-align:left;}
  th{background-color:#f2f2f2;}.header{display:flex;justify-content:space-between;align-items:center;}
  .logout-btn{padding:8px 16px;background:#dc3545;color:#fff;text-decoration:none;border-radius:4px;}
  .logout-btn:hover{background:#c82333;}
  .delete-btn{padding:6px 12px;background:#ff6b6b;color:#fff;border:none;border-radius:3px;cursor:pointer;}
  .delete-btn:hover{background:#ee5a52;}
  </style>
  <script>
    function deleteEmail(id) {
      if (confirm('确定要删除该邮件吗？')) {
        fetch('/delete/' + id, { method: 'POST' }).then(() => location.reload());
      }
    }
  </script>
  </head>
  <body><div class="header"><h1>📬 邮件收件箱 (${messages.length} 封)</h1><a href="/logout" class="logout-btn">退出登录</a></div>
  <table><thead><tr><th>收件人</th><th>发件人</th><th>主题</th><th>接收时间</th><th>状态</th><th>操作</th></tr></thead>
  <tbody>${rows || '<tr><td colspan="6">暂无邮件</td></tr>'}</tbody></table></body></html>`;
}

function generateDetailPage(message) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>📄 ${escapeHtml(message.subject)}</title>
  <style>body{font-family:sans-serif;max-width:800px;margin:20px auto;padding:0 20px;}
  .back-link{display:inline-block;margin-bottom:20px;}.email-meta{background:#f8f9fa;padding:15px;border-radius:4px;margin-bottom:20px;}
  .email-content{white-space:pre-wrap;word-wrap:break-word;}.email-content img{max-width:100%;}
  .actions{margin-top:20px;display:flex;gap:10px;}
  .delete-btn{padding:10px 16px;background:#dc3545;color:#fff;border:none;border-radius:4px;cursor:pointer;}
  .delete-btn:hover{background:#c82333;}
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
  <body><a href="/" class="back-link">← 返回收件箱</a><h1>${escapeHtml(message.subject)}</h1>
  <div class="email-meta"><p><strong>发件人:</strong> ${escapeHtml(message.from_address)}</p>
  <p><strong>收件人:</strong> ${escapeHtml(message.mailbox_email)}</p>
  <p><strong>接收时间:</strong> ${new Date(message.received_at).toLocaleString()}</p></div>
  <div class="email-content">${message.html_content ? message.html_content : escapeHtml(message.content || '(无内容)')}</div>
  <div class="actions">
    <button class="delete-btn" onclick="deleteAndGoBack()">🗑️ 删除邮件</button>
  </div>
  </body></html>`;
}

function escapeHtml(unsafe) {
  if (!unsafe) return '';
  return unsafe.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}
