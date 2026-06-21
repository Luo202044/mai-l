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
    
    // 实时读取最新的配置（支持免重启重新加载，支持逗号分隔多密码）
    const PASSWORD_RAW = env.PASSWORD || 'admin123';
    const SECRET_KEY = env.SECRET_KEY || 'your-secret-key-change-me';

    // 动态解析多密码列表（过滤空格和空字符串）
    const getPasswordList = () => {
      return PASSWORD_RAW.split(',').map(p => p.trim()).filter(Boolean);
    };

    // 辅助函数：计算单密码的摘要值，用于 Token 隔离
    const getPwdHash = async (pwd) => {
      const encoder = new TextEncoder();
      const data = encoder.encode(pwd);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    };

    // 基于 HMAC-SHA256 的安全 Token 生成（绑定特定密码哈希）
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

    // 严格的 Token 校验（校验时实时比对当前的有效密码列表）
    const checkAuth = async (req) => {
      const cookies = parseCookies(req.headers.get('Cookie') || '');
      if (!cookies.auth_token) return false;
      
      const parts = cookies.auth_token.split('.');
      if (parts.length !== 3) return false;
      
      const [timestampStr, tokenPwdHash, hash] = parts;
      const timestamp = parseInt(timestampStr, 10);
      
      // 1. 检查 Token 是否过期（有效期 24 小时）
      if (isNaN(timestamp) || Date.now() - timestamp > 86400000) return false;
      
      // 2. 重新计算签名，验证 Token 是否被篡改
      const expectedToken = await generateToken(timestamp, tokenPwdHash);
      if (cookies.auth_token !== expectedToken) return false;

      // 3. 动态配置重载核心：验证当前 Token 里的密码哈希，是否依然存在于最新的密码列表中
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

    // 路由: 登录页
    if (path === '/login' && request.method === 'GET') {
      return new Response(generateLoginPage(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    // 路由: 登录提交
    if (path === '/login' && request.method === 'POST') {
      try {
        const formData = await request.formData();
        const inputPassword = formData.get('password') || '';
        const currentPasswords = getPasswordList();
        
        // 匹配任意一个有效密码
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

    // 路由: 邮件列表 (需要鉴权)
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

    // 路由: 查看邮件详情 (需要鉴权)
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

    // 路由: 渲染 HTML 邮件原始内容 (专门供给 iframe 的安全沙箱)
    if (path.startsWith('/raw-html/')) {
      if (!(await checkAuth(request))) {
        return new Response('Unauthorized', { status: 401 });
      }
      const messageId = path.split('/')[2];
      const message = await env.DB.prepare('SELECT html_content, content FROM messages WHERE id = ?').bind(messageId).first();
      if (!message) return new Response('Not Found', { status: 404 });
      
      const body = message.html_content || `<pre style="white-space: pre-wrap; font-family: monospace;">${escapeHtml(message.content)}</pre>`;
      return new Response(body, {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Security-Policy': "default-src 'self' http: https: data: 'unsafe-inline'; script-src 'none'; object-src 'none';" 
        }
      });
    }

    // 路由: 删除邮件 (需要鉴权)
    if (path.startsWith('/delete/')) {
      if (!(await checkAuth(request))) {
        return new Response(null, { status: 302, headers: { 'Location': '/login' } });
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

    // 路由: 登出
    if (path === '/logout') {
      return new Response(null, {
        status: 302,
        headers: {
          'Location': '/login',
          'Set-Cookie': 'auth_token=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0'
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
    console.log('✅ 数据库表验证成功');
  } catch (err) {
    console.error('❌ 自动建表失败:', err);
  }
}

// --- 以下为 HTML 模板函数 ---
function escapeHtml(unsafe) {
  if (!unsafe) return '';
  return unsafe.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}

function generateLoginPage(errorMessage = '') {
  // 注意：已修复 <div class="login-header"> 闭合缺失的问题
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>📧 邮件收件箱 - 登录</title><style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);min-height:100vh;display:flex;justify-content:center;align-items:center;padding:20px;color:#f8fafc;}.login-container{background:#1e293b;border:1px solid #334155;border-radius:12px;box-shadow:0 10px 25px -5px rgba(0,0,0,0.3);width:100%;max-width:400px;padding:40px;}.login-header{text-align:center;margin-bottom:30px;}.login-header h2{font-size:24px;margin-top:10px;color:#f1f5f9;}.login-header p{color:#94a3b8;font-size:14px;margin-top:5px;}.form-group{margin-bottom:20px;}.form-group label{display:block;margin-bottom:8px;color:#cbd5e1;font-weight:500;font-size:14px;}.form-group input{width:100%;padding:12px;background:#0f172a;border:1px solid #334155;border-radius:6px;font-size:14px;color:#fff;transition:border-color 0.3s;}.form-group input:focus{outline:none;border-color:#3b82f6;}.submit-btn{width:100%;padding:12px;background:#3b82f6;color:white;border:none;border-radius:6px;font-size:16px;font-weight:600;cursor:pointer;transition:background 0.2s;}.submit-btn:hover{background:#2563eb;}.error-message{color:#ef4444;font-size:14px;margin-bottom:20px;padding:10px;background-color:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.2);border-radius:6px;}</style></head><body><div class="login-container"><div class="login-header"><h1>📧</h1><h2>邮件收件箱</h2><p>请输入密码以继续</p></div><form method="POST" action="/login">${errorMessage?`<div class="error-message">${escapeHtml(errorMessage)}</div>`:''}<div class="form-group"><label for="password">安全密码</label><input type="password" id="password" name="password" required autofocus placeholder="••••••••"></div><button type="submit" class="submit-btn">验证登录</button></form></div></body></html>`;
}

function generateListPage(messages) {
  const rows = messages.map(msg => `<tr class="${msg.is_read ? 'read' : 'unread'}"><td style="font-weight: 500; color:#334155;">${escapeHtml(msg.mailbox_email)}</td><td>${escapeHtml(msg.from_address)}</td><td><a class="subject-link" href="/view/${msg.id}">${escapeHtml(msg.subject || '(无主题)')}</a></td><td class="time-col">${new Date(msg.received_at).toLocaleString('zh-CN', {hour12:false})}</td><td><span class="badge ${msg.is_read ? 'badge-read' : 'badge-unread'}">${msg.is_read ? '已读' : '未读'}</span></td><td><button class="delete-btn" onclick="deleteEmail(${msg.id}, event)">删除</button></td></tr>`).join('');
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>📧 收件箱</title><style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background-color:#f8fafc;color:#1e293b;padding:30px 20px;}.container{max-width:1200px;margin:0 auto;}.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;background:white;padding:20px 24px;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.05);}.header h1{font-size:20px;font-weight:700;color:#0f172a;}.logout-btn{padding:8px 16px;background:#f1f5f9;color:#64748b;text-decoration:none;border-radius:6px;font-size:14px;font-weight:500;transition:all 0.2s;}.logout-btn:hover{background:#e2e8f0;color:#0f172a;}.table-wrapper{background:white;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.05);overflow:hidden;}table{width:100%;border-collapse:collapse;text-align:left;font-size:14px;}th{background:#f8fafc;padding:16px;font-weight:600;color:#64748b;border-bottom:1px solid #e2e8f0;}td{padding:16px;border-bottom:1px solid #f1f5f9;color:#334155;}tr:hover{background-color:#f8fafc;}tr.unread{background-color:#f0fdf4;}tr.unread:hover{background-color:#dcfce7;}.subject-link{color:#2563eb;text-decoration:none;font-weight:500;}.subject-link:hover{text-decoration:underline;}.badge{padding:4px 8px;border-radius:4px;font-size:12px;font-weight:500;}.badge-unread{background:#dcfce7;color:#166534;}.badge-read{background:#f1f5f9;color:#64748b;}.delete-btn{padding:6px 12px;background:#fff;color:#ef4444;border:1px solid #fee2e2;border-radius:6px;cursor:pointer;transition:all 0.2s;}.delete-btn:hover{background:#ef4444;color:#fff;}.empty{text-align:center;padding:60px;color:#94a3b8;font-size:16px;}.time-col{color:#64748b;font-variant-numeric:tabular-nums;}</style><script>function deleteEmail(id,e){e.preventDefault();if(confirm('确定要彻底删除该邮件吗？')){fetch('/delete/'+id,{method:'POST'}).then(()=>location.reload());}}</script></head><body><div class="container"><div class="header"><h1>📬 临时收件箱 (${messages.length})</h1><a href="/logout" class="logout-btn">安全退出</a></div><div class="table-wrapper"><table><thead><tr><th>别名收件箱</th><th>发件人</th><th>邮件主题</th><th>到达时间</th><th>状态</th><th>管理</th></tr></thead><tbody>${rows?rows:'<tr><td colspan="6" class="empty">📭 暂无任何邮件，请将邮件发送至您的路由别名。</td></tr>'}</tbody></table></div></div></body></html>`;
}

function generateDetailPage(message) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${escapeHtml(message.subject || '查看邮件')}</title><style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background-color:#f8fafc;color:#1e293b;padding:30px 20px;}.container{max-width:900px;margin:0 auto;}.back-btn{display:inline-flex;align-items:center;padding:8px 14px;background:white;border:1px solid #e2e8f0;border-radius:6px;color:#475569;text-decoration:none;font-size:14px;margin-bottom:20px;box-shadow:0 1px 2px rgba(0,0,0,0.05);}.back-btn:hover{background:#f8fafc;color:#0f172a;}.card{background:white;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.05);padding:30px;margin-bottom:20px;}.subject{font-size:22px;font-weight:700;color:#0f172a;margin-bottom:20px;line-height:1.4;}.meta-grid{display:grid;grid-template-columns:auto 1fr;gap:10px 16px;font-size:14px;border-bottom:1px solid #f1f5f9;padding-bottom:20px;margin-bottom:20px;}.meta-label{color:#64748b;font-weight:500;}.meta-value{color:#334155;}.iframe-container{width:100%;border:1px solid #e2e8f0;border-radius:8px;background:#fff;overflow:hidden;margin-top:10px;}iframe{width:100%;min-height:500px;border:none;display:block;}.danger-zone{display:flex;justify-content:flex-end;}.delete-btn{padding:10px 20px;background:#fee2e2;color:#ef4444;border:1px solid #fca5a5;border-radius:6px;cursor:pointer;font-weight:600;font-size:14px;transition:all 0.2s;}.delete-btn:hover {background:#ef4444;color:white;}</style><script>function deleteAndGoBack(){if(confirm('确定要彻底删除该邮件并返回收件箱吗？')){fetch('/delete/${message.id}',{method:'POST'}).then(()=>{window.location.href='/';});}}function resizeIframe(obj){setTimeout(()=>{try{obj.style.height=obj.contentWindow.document.documentElement.scrollHeight+40+'px';}catch(e){obj.style.height='600px';}},200);}</script></head><body><div class="container"><a href="/" class="back-btn">← 返回收件箱</a><div class="card"><div class="subject">${escapeHtml(message.subject||'(无主题)')}</div><div class="meta-grid"><div class="meta-label">发件人</div><div class="meta-value">${escapeHtml(message.from_address)}</div><div class="meta-label">收件别名</div><div class="meta-value">${escapeHtml(message.mailbox_email)}</div><div class="meta-label">时间</div><div class="meta-value">${new Date(message.received_at).toLocaleString()}</div></div><div class="iframe-container"><iframe src="/raw-html/${message.id}" sandbox="allow-popups allow-popups-to-escape-sandbox" onload="resizeIframe(this)"></iframe></div></div><div class="danger-zone"><button class="delete-btn" onclick="deleteAndGoBack()">🗑️ 彻底删除邮件</button></div></div></body></html>`;
}
