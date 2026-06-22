import PostalMime from 'postal-mime';

// ==========================================
// 1. 数据库初始化 SQL (包含用户、设置、日志、邮件)
// ==========================================
const CREATE_TABLES_SQL = `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    role TEXT NOT NULL,
    permissions TEXT NOT NULL,
    accessible_emails TEXT NOT NULL,
    token_version INTEGER DEFAULT 1,
    disabled BOOLEAN DEFAULT 0,
    created_by INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_token_version ON users(token_version);

CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_by INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    details TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_logs_created_at ON audit_logs(created_at);

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

// ==========================================
// 2. 全局状态与内存缓存
// ==========================================
let tablesReady = false;
let configCache = null;
let cacheTimestamp = 0;

export default {
  async email(message, env, ctx) {
    await ensureTables(env);
    const toAddress = message.to;
    if (!toAddress) return;

    try {
      const config = await getSystemConfig(env);
      if (config.allowed_domains && config.allowed_domains.length > 0) {
        const domain = toAddress.split('@')[1];
        if (!config.allowed_domains.includes(domain)) {
          console.warn(`⚠️ 拒收非白名单域名的邮件: ${toAddress}`);
          return;
        }
      }

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
    } catch (error) {
      console.error('❌ 处理邮件失败:', error);
    }
  },

  async fetch(request, env, ctx) {
    await ensureTables(env);
    const url = new URL(request.url);
    const path = url.pathname;
    
    // 🔥 修复日志缺失 Bug 1：在此处提取真实的客户端 IP 和 UA
    const clientIp = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
    const userAgent = request.headers.get('User-Agent') || 'Unknown';

    const SUPER_USER = env.SUPER_USERNAME || 'superuser';
    const SUPER_PASS = env.SUPER_PASSWORD || 'superpassword123';
    const JWT_SECRET = env.JWT_SECRET || 'a-very-secret-string-more-than-32-chars';

    const hashPassword = async (password) => {
      const encoder = new TextEncoder();
      const salt = encoder.encode('cf_mail_worker_salt_fixed'); 
      const baseKey = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits', 'deriveKey']);
      const derivedKey = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
        baseKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt']
      );
      const exported = await crypto.subtle.exportKey('raw', derivedKey);
      return Array.from(new Uint8Array(exported)).map(b => b.toString(16).padStart(2, '0')).join('');
    };

    const base64UrlEncode = (str) => btoa(str).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const base64UrlDecode = (str) => {
      str = str.replace(/-/g, '+').replace(/_/g, '/');
      while (str.length % 4) str += '=';
      return atob(str);
    };

    const generateJWT = async (payload) => {
      const header = { alg: 'HS256', typ: 'JWT' };
      const encodedHeader = base64UrlEncode(JSON.stringify(header));
      const encodedPayload = base64UrlEncode(JSON.stringify(payload));
      
      const encoder = new TextEncoder();
      const key = await crypto.subtle.importKey('raw', encoder.encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(`${encodedHeader}.${encodedPayload}`));
      const encodedSignature = base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));
      
      return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
    };

    const verifyJWT = async (token) => {
      try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        const [encodedHeader, encodedPayload, encodedSignature] = parts;
        
        const encoder = new TextEncoder();
        const key = await crypto.subtle.importKey('raw', encoder.encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
        const data = encoder.encode(`${encodedHeader}.${encodedPayload}`);
        
        const sigBytes = new Uint8Array(base64UrlDecode(encodedSignature).split('').map(c => c.charCodeAt(0)));
        const valid = await crypto.subtle.verify('HMAC', key, sigBytes, data);
        
        if (!valid) return null;
        const payload = JSON.parse(base64UrlDecode(encodedPayload));
        if (Date.now() > payload.exp) return null; 
        return payload;
      } catch (e) {
        return null;
      }
    };

    const getSession = async () => {
      const cookies = parseCookies(request.headers.get('Cookie') || '');
      if (!cookies.auth_token) return null;
      
      const payload = await verifyJWT(cookies.auth_token);
      if (!payload) return null;

      if (payload.user_id === 0) return payload;

      const dbUser = await env.DB.prepare('SELECT token_version, disabled, permissions, accessible_emails FROM users WHERE id = ?')
        .bind(payload.user_id).first();
      
      if (!dbUser || dbUser.disabled === 1 || dbUser.token_version !== payload.token_version) return null; 

      payload.permissions = JSON.parse(dbUser.permissions);
      payload.accessible_emails = JSON.parse(dbUser.accessible_emails);
      return payload;
    };

    // 🔥 修复日志缺失 Bug 2：补充了 clientIp 和 userAgent 的绑定参数
    const logAction = (userId, username, action, targetType, targetId, description, success) => {
      ctx.waitUntil((async () => {
        try {
          await env.DB.prepare(
            `INSERT INTO audit_logs (user_id, username, action, target_type, target_id, details, ip, user_agent, success)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).bind(userId, username, action, targetType, targetId ? String(targetId) : null, JSON.stringify({ description }), clientIp, userAgent, success ? 1 : 0).run();
        } catch (e) {
          console.error('写入审计日志失败:', e);
        }
      })());
    };

    // ------------------------------------------
    // ⚙️ 路由处理
    // ------------------------------------------
    
    // API: 登录提交
    if (path === '/api/login' && request.method === 'POST') {
      try {
        const formData = await request.formData();
        const username = formData.get('username') || '';
        const password = formData.get('password') || '';
        const config = await getSystemConfig(env);
        const expiryHours = config.session_expiry_hours || 24;

        if (username === SUPER_USER && password === SUPER_PASS) {
          const jwt = await generateJWT({ user_id: 0, username: SUPER_USER, role: 'superuser', permissions: ['*'], token_version: 0, exp: Date.now() + (expiryHours * 60 * 60 * 1000) });
          logAction(0, SUPER_USER, 'login', 'user', '0', '成功登入系统', true);
          return new Response(JSON.stringify({ success: true }), {
            headers: { 'Content-Type': 'application/json', 'Set-Cookie': `auth_token=${jwt}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${expiryHours * 3600}` }
          });
        }

        const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
        if (user) {
          if (user.disabled === 1) {
            logAction(user.id, username, 'login', 'user', user.id, '账户已被封禁阻断', false);
            return new Response(JSON.stringify({ success: false, message: '账户已被封禁' }), { status: 403 });
          }
          const inputHash = await hashPassword(password);
          if (inputHash === user.password_hash) {
            const jwt = await generateJWT({ user_id: user.id, username: user.username, role: user.role, permissions: JSON.parse(user.permissions), token_version: user.token_version, exp: Date.now() + (expiryHours * 60 * 60 * 1000) });
            logAction(user.id, username, 'login', 'user', user.id, '成功登入系统', true);
            return new Response(JSON.stringify({ success: true }), {
              headers: { 'Content-Type': 'application/json', 'Set-Cookie': `auth_token=${jwt}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${expiryHours * 3600}` }
            });
          }
        }

        logAction(-1, username, 'login', 'user', null, '凭证不匹配拦截', false);
        return new Response(JSON.stringify({ success: false, message: '用户名或密码错误' }), { status: 401 });
      } catch (e) {
        return new Response(JSON.stringify({ success: false, message: e.message }), { status: 500 });
      }
    }

    if (path === '/login' && request.method === 'GET') {
      return new Response(generateLoginPage(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    if (path === '/logout') {
      const session = await getSession();
      if (session) logAction(session.user_id, session.username, 'logout', 'user', session.user_id, '注销并退出系统', true);
      return new Response(null, { status: 302, headers: { 'Location': '/login', 'Set-Cookie': 'auth_token=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0' }});
    }

    // 🛡️ JWT 鉴权
    const session = await getSession();
    if (!session) return new Response(null, { status: 302, headers: { 'Location': '/login' } });
    const hasPermission = (perm) => session.role === 'superuser' || session.permissions.includes(perm);

    if (path === '/' || path === '') {
      try {
        let querySql = `SELECT m.*, mb.email as mailbox_email FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id`;
        let bindParams = [];

        if (session.role !== 'superuser' && !hasPermission('mail:view:all')) {
          let conditions = [];
          if (hasPermission('mail:view:own') && session.email) {
            conditions.push(`mb.email = ?`); bindParams.push(session.email);
          }
          if (hasPermission('mail:view:allowed') && session.accessible_emails) {
            session.accessible_emails.forEach(allowed => {
              if (allowed.startsWith('@')) { conditions.push(`mb.email LIKE ?`); bindParams.push(`%${allowed}`); } 
              else { conditions.push(`mb.email = ?`); bindParams.push(allowed); }
            });
          }
          if (conditions.length === 0) return new Response(generateListPage([], session), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
          querySql += ` WHERE ` + conditions.join(' OR ');
        }

        querySql += ` ORDER BY m.received_at DESC LIMIT 100`;
        const stmt = env.DB.prepare(querySql);
        const messages = await (bindParams.length > 0 ? stmt.bind(...bindParams) : stmt).all();
        // 首页仅加载，不记录日志防止日志库污染膨胀
        return new Response(generateListPage(messages.results, session), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      } catch (e) {
        return new Response('系统错误: ' + e.message, { status: 500 });
      }
    }

    if (path.startsWith('/view/')) {
      const messageId = path.split('/')[2];
      try {
        const message = await env.DB.prepare(`SELECT m.*, mb.email as mailbox_email FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id WHERE m.id = ?`).bind(messageId).first();
        if (!message) return new Response('邮件不存在', { status: 404 });

        if (!checkMailAccess(session, message.mailbox_email, 'view')) {
          logAction(session.user_id, session.username, 'access_denied', 'message', messageId, `越权尝试查看他人邮件`, false);
          return new Response('无权查看该邮件', { status: 403 });
        }

        await env.DB.prepare('UPDATE messages SET is_read = 1 WHERE id = ?').bind(messageId).run();
        logAction(session.user_id, session.username, 'view_message', 'message', messageId, `阅读邮件: ${message.subject}`, true);
        return new Response(generateDetailPage(message, session), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      } catch (e) { return new Response('错误: ' + e.message, { status: 500 }); }
    }

    if (path.startsWith('/raw-html/')) {
      const messageId = path.split('/')[2];
      const message = await env.DB.prepare('SELECT m.html_content, m.content, mb.email FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id WHERE m.id = ?').bind(messageId).first();
      if (!message || !checkMailAccess(session, message.email, 'view')) return new Response('Forbidden', { status: 403 });
      const body = message.html_content || `<pre style="white-space: pre-wrap; font-family: monospace; padding:12px; color:#1e293b;">${escapeHtml(message.content)}</pre>`;
      return new Response(body, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': "default-src 'self' http: https: data: 'unsafe-inline'; script-src 'none'; object-src 'none';" }});
    }

    if (path.startsWith('/delete/') && request.method === 'POST') {
      const messageId = path.split('/')[2];
      try {
        const message = await env.DB.prepare('SELECT mb.email, m.subject FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id WHERE m.id = ?').bind(messageId).first();
        if (!message) return new Response('邮件未找到', { status: 404 });

        if (!checkMailAccess(session, message.email, 'delete')) {
          logAction(session.user_id, session.username, 'access_denied', 'message', messageId, `越权尝试删除他人邮件`, false);
          return new Response('无操作权限', { status: 403 });
        }

        await env.DB.prepare('DELETE FROM messages WHERE id = ?').bind(messageId).run();
        logAction(session.user_id, session.username, 'delete_message', 'message', messageId, `物理清除了邮件: ${message.subject}`, true);
        return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
      } catch (e) { return new Response(e.message, { status: 500 }); }
    }

    if (path === '/admin/users') {
      if (!hasPermission('user:manage:restricted') && !hasPermission('user:manage:all')) return new Response('无权访问管理面板', { status: 403 });

      if (request.method === 'GET') {
        const users = await env.DB.prepare('SELECT id, username, email, role, permissions, accessible_emails, disabled, created_at FROM users ORDER BY id DESC').all();
        return new Response(generateUserPage(users.results, session), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }

      if (request.method === 'POST') {
        try {
          const body = await request.json();
          const { action, id, username, password, email, role, permissions, accessible_emails, disabled } = body;

          if (!hasPermission('user:manage:all') && role === 'admin') return new Response(JSON.stringify({ success: false, message: '您无权管理管理员账户' }), { status: 403 });

          if (action === 'create') {
            const pwdHash = await hashPassword(password);
            await env.DB.prepare(
              `INSERT INTO users (username, password_hash, email, role, permissions, accessible_emails, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)`
            ).bind(username, pwdHash, email || null, role, JSON.stringify(permissions), JSON.stringify(accessible_emails), session.user_id).run();
            logAction(session.user_id, session.username, 'create_user', 'user', null, `新增系统账户: ${username} [${role}]`, true);
            return new Response(JSON.stringify({ success: true }));
          }

          if (action === 'update') {
            const target = await env.DB.prepare('SELECT role, permissions, accessible_emails FROM users WHERE id = ?').bind(id).first();
            if (target.role === 'admin' && !hasPermission('user:manage:all')) return new Response(JSON.stringify({ success: false, message: '权限不足，无法编辑高管' }), { status: 403 });

            let updateSql = `UPDATE users SET email = ?, role = ?, permissions = ?, accessible_emails = ?, disabled = ?, token_version = token_version + 1`;
            let params = [email || null, role, JSON.stringify(permissions), JSON.stringify(accessible_emails), disabled ? 1 : 0];

            if (password && password.trim() !== '') {
              const newHash = await hashPassword(password);
              updateSql += `, password_hash = ?`; params.push(newHash);
            }
            updateSql += ` WHERE id = ?`; params.push(id);
            await env.DB.prepare(updateSql).bind(...params).run();
            
            // 🔥 精准记录：是改了信息还是改了权限？
            logAction(session.user_id, session.username, 'update_user', 'user', id, `编辑基础账户信息: ${username}`, true);
            if (target.permissions !== JSON.stringify(permissions) || target.accessible_emails !== JSON.stringify(accessible_emails)) {
              logAction(session.user_id, session.username, 'update_permission', 'user', id, `更改了权限清单或可视邮箱白名单: ${username}`, true);
            }
            return new Response(JSON.stringify({ success: true }));
          }

          if (action === 'delete') {
            if (!hasPermission('user:manage:all')) return new Response(JSON.stringify({ success: false, message: '权限不足' }), { status: 403 });
            await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
            logAction(session.user_id, session.username, 'delete_user', 'user', id, `注销并删除了账户 ID: ${id}`, true);
            return new Response(JSON.stringify({ success: true }));
          }
        } catch (e) { return new Response(JSON.stringify({ success: false, message: e.message }), { status: 500 }); }
      }
    }

    if (path === '/admin/logs' && hasPermission('log:view:all')) {
      const logs = await env.DB.prepare('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 200').all();
      logAction(session.user_id, session.username, 'view_logs', 'log', null, `调阅了全局系统审计日志`, true);
      return new Response(generateLogPage(logs.results, session), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    if (path === '/admin/settings' && hasPermission('system:config:view')) {
      if (request.method === 'GET') {
        const config = await getSystemConfig(env);
        return new Response(generateSettingsPage(config, session), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }

      if (request.method === 'POST' && hasPermission('system:config:edit')) {
        try {
          const body = await request.json();
          await env.DB.prepare('INSERT OR REPLACE INTO system_config (key, value, updated_by) VALUES (?, ?, ?)')
            .bind('allowed_domains', JSON.stringify(body.allowed_domains || []), session.user_id).run();
          await env.DB.prepare('INSERT OR REPLACE INTO system_config (key, value, updated_by) VALUES (?, ?, ?)')
            .bind('session_expiry_hours', JSON.stringify(parseInt(body.session_expiry_hours, 10) || 24), session.user_id).run();
          configCache = null; 
          logAction(session.user_id, session.username, 'update_system_config', 'system_config', null, '重新设定了系统环境策略配置', true);
          return new Response(JSON.stringify({ success: true }));
        } catch (e) { return new Response(JSON.stringify({ success: false, message: e.message }), { status: 500 }); }
      }
    }
    return new Response('Not Found', { status: 404 });
  }
};

function checkMailAccess(session, targetEmail, type) {
  if (session.role === 'superuser' || session.permissions.includes(`mail:${type}:all`)) return true;
  if (session.permissions.includes(`mail:${type}:own`) && session.email === targetEmail) return true;
  if (session.permissions.includes(`mail:${type}:allowed`) && session.accessible_emails) {
    return session.accessible_emails.some(allowed => {
      if (allowed.startsWith('@')) return targetEmail.endsWith(allowed);
      return allowed === targetEmail;
    });
  }
  return false;
}

async function getSystemConfig(env) {
  const now = Date.now();
  if (configCache && (now - cacheTimestamp < 60000)) return configCache; 
  const rows = await env.DB.prepare('SELECT key, value FROM system_config').all();
  const config = { allowed_domains: [], session_expiry_hours: 24 };
  rows.results.forEach(row => { config[row.key] = JSON.parse(row.value); });
  configCache = config; cacheTimestamp = now;
  return config;
}

async function ensureTables(env) {
  if (tablesReady) return;
  try { await env.DB.exec(CREATE_TABLES_SQL); tablesReady = true; } catch (err) {}
}

function parseCookies(header) {
  const cookies = {};
  if (header) {
    header.split(';').forEach(c => {
      const [name, value] = c.trim().split('=');
      if (name && value) cookies[name] = decodeURIComponent(value);
    });
  }
  return cookies;
}

function getHeaderNav(session) {
  const hasUserManage = session.role === 'superuser' || session.permissions.includes('user:manage:restricted') || session.permissions.includes('user:manage:all');
  const hasLogs = session.role === 'superuser' || session.permissions.includes('log:view:all');
  const hasSettings = session.role === 'superuser' || session.permissions.includes('system:config:view');

  return `
    <div class="header">
      <div class="nav-brand"><a href="/" style="color:#0f172a; text-decoration:none;">📬 邮件收件箱</a></div>
      <div class="nav-links">
        <a href="/" class="nav-item">列表</a>
        ${hasUserManage ? `<a href="/admin/users" class="nav-item">用户</a>` : ''}
        ${hasLogs ? `<a href="/admin/logs" class="nav-item">审计</a>` : ''}
        ${hasSettings ? `<a href="/admin/settings" class="nav-item">系统</a>` : ''}
        <a href="/logout" class="logout-btn">退出</a>
      </div>
    </div>
    <div class="user-badge">当前会话主体: <strong>${session.username}</strong> [${session.role.toUpperCase()}]</div>
  `;
}

function generateLoginPage() {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>安全认证登录</title>
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family:-apple-system,system-ui,sans-serif; background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); min-height:100vh; display:flex; justify-content:center; align-items:center; padding:16px; color:#f8fafc; }
    .card { background:#1e293b; border:1px solid #334155; border-radius:16px; width:100%; max-width:360px; padding:32px 24px; box-shadow:0 10px 25px -5px rgba(0,0,0,0.5); }
    .h { text-align:center; margin-bottom:24px; }
    .h h2 { font-size:20px; color:#f1f5f9; }
    .g { margin-bottom:16px; }
    .g label { display:block; margin-bottom:6px; color:#cbd5e1; font-size:14px; }
    .g input { width:100%; padding:12px; background:#0f172a; border:1px solid #334155; border-radius:8px; color:#fff; font-size:14px; }
    .g input:focus { outline:none; border-color:#3b82f6; }
    .btn { width:100%; padding:12px; background:#3b82f6; color:#fff; border:none; border-radius:8px; font-size:15px; font-weight:600; cursor:pointer; }
    .err { color:#ef4444; background:rgba(239,68,68,0.1); padding:10px; border-radius:6px; margin-bottom:16px; font-size:13px; display:none; }
  </style></head>
  <body>
    <div class="card">
      <div class="h"><h2>📧 邮件接收管理系统</h2></div>
      <div class="err" id="e"></div>
      <form id="f">
        <div class="g"><label>用户名</label><input type="text" id="u" required autofocus></div>
        <div class="g"><label>安全密码</label><input type="password" id="p" required></div>
        <button type="submit" class="btn">安全登录</button>
      </form>
    </div>
    <script>
      document.getElementById('f').onsubmit = async (e) => {
        e.preventDefault();
        const err = document.getElementById('e');
        err.style.display = 'none';
        const fd = new URLSearchParams();
        fd.append('username', document.getElementById('u').value);
        fd.append('password', document.getElementById('p').value);
        const res = await fetch('/api/login', { method:'POST', body:fd });
        if(res.ok) { window.location.href = '/'; } 
        else { const data = await res.json(); err.innerText = data.message; err.style.display='block'; }
      }
    </script>
  </body></html>`;
}

function generateListPage(messages, session) {
  const rows = messages.map(msg => `
    <tr>
      <td data-label="专属收件箱" style="font-weight:600; color:#0f172a;">${escapeHtml(msg.mailbox_email)}</td>
      <td data-label="发件人">${escapeHtml(msg.from_address)}</td>
      <td data-label="邮件主题"><a class="link" href="/view/${msg.id}">${msg.is_read ? '' : '✉️ '}${escapeHtml(msg.subject || '(无主题)')}</a></td>
      <td data-label="到达时间" style="color:#64748b;">${new Date(msg.received_at).toLocaleString('zh-CN')}</td>
      <td data-label="管理"><button class="del-btn" onclick="delMail(${msg.id})">删除</button></td>
    </tr>
  `).join('');

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>邮件收件箱</title>
  <style>${getCommonCss()}
    @media(max-width:768px){
      thead{display:none;} tr{display:block; background:#fff; border-radius:8px; margin-bottom:12px; padding:12px; box-shadow:0 1px 2px rgba(0,0,0,0.05);}
      td{display:flex; justify-content:space-between; padding:6px 0; border:none; text-align:right;}
      td::before{content:attr(data-label); color:#64748b; font-weight:500;}
      .del-btn{width:100%; text-align:center; margin-top:6px;}
    }
  </style></head>
  <body>
    <div class="container">
      ${getHeaderNav(session)}
      <div class="wrapper" style="overflow-x:auto;">
        <table>
          <thead><tr><th>别名收件箱</th><th>发件人</th><th>主题</th><th>接收时间</th><th>操作</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="5" style="text-align:center;color:#94a3b8;">📭 目前尚无任何可支配的邮件。</td></tr>'}</tbody>
        </table>
      </div>
    </div>
    <script>
      async function delMail(id) {
        if(confirm('核实要彻底删除此邮件记录吗？')) {
          const res = await fetch('/delete/' + id, { method:'POST' });
          if(res.ok) location.reload(); else alert('无权删除或操作被拦截');
        }
      }
    </script>
  </body></html>`;
}

function generateDetailPage(message, session) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>邮件详情</title>
  <style>${getCommonCss()}
    .card { background:#fff; padding:20px; border-radius:12px; box-shadow:0 1px 3px rgba(0,0,0,0.05); }
    .sub { font-size:18px; font-weight:700; margin-bottom:16px; color:#0f172a; word-break:break-all; }
    .grid { display:grid; grid-template-columns:auto 1fr; gap:8px 16px; font-size:13px; margin-bottom:20px; padding-bottom:16px; border-bottom:1px solid #f1f5f9; }
    .lbl { color:#64748b; font-weight:500; }
    iframe { width:100%; min-height:450px; border:1px solid #e2e8f0; border-radius:8px; display:block; }
  </style></head>
  <body>
    <div class="container">
      ${getHeaderNav(session)}
      <a href="/" class="btn" style="display:inline-block; margin-bottom:12px; text-decoration:none; background:#f1f5f9; color:#475569;">← 返回收件箱</a>
      <div class="card">
        <div class="sub">${escapeHtml(message.subject || '(无主题)')}</div>
        <div class="grid">
          <div class="lbl">发件人</div><div>${escapeHtml(message.from_address)}</div>
          <div class="lbl">收件人</div><div>${escapeHtml(message.mailbox_email)}</div>
          <div class="lbl">到达时间</div><div>${new Date(message.received_at).toLocaleString()}</div>
        </div>
        <iframe src="/raw-html/${message.id}" sandbox="allow-popups allow-popups-to-escape-sandbox"></iframe>
      </div>
    </div>
  </body></html>`;
}

function generateUserPage(users, session) {
  const AVAILABLE_PERMISSIONS = [
    { key: 'mail:view:own', label: '查看专属邮箱邮件', desc: '仅允许查看与自己绑定的专属邮箱邮件' },
    { key: 'mail:view:allowed', label: '查看授权箱/域邮件', desc: '允许查看在穿透列表中指定的邮箱或域名后缀邮件' },
    { key: 'mail:view:all', label: '查看全局所有邮件', desc: '拥有全局邮件查看最高特权' },
    { key: 'mail:delete:own', label: '删除专属邮箱邮件', desc: '允许删除自己专属邮箱接收到的邮件' },
    { key: 'mail:delete:allowed', label: '删除授权箱/域邮件', desc: '允许删除穿透列表中指定的目标邮件' },
    { key: 'mail:delete:all', label: '删除全局所有邮件', desc: '可任意粉碎系统内的任何邮件' },
    { key: 'user:manage:restricted', label: '受限管理普通用户', desc: '仅允许增删改普通（USER）角色' },
    { key: 'user:manage:all', label: '全权管理所有账户', desc: '可管理包含普通管理员在内的所有账户' },
    { key: 'log:view:all', label: '调阅全局审计日志', desc: '允许查看全量底层用户操作轨迹安全日志' },
    { key: 'system:config:view', label: '查阅全局系统设置', desc: '对接收域名后缀白名单等安全设置只读可见' },
    { key: 'system:config:edit', label: '修改全局系统设置', desc: '允许改写动态热重载系统配置' }
  ];

  const rows = users.map(u => `
    <tr>
      <td data-label="用户名" style="font-weight:600; color:#0f172a;">${escapeHtml(u.username)}</td>
      <td data-label="角色"><span class="badge" style="background:#e0f2fe;color:#0369a1;">${u.role.toUpperCase()}</span></td>
      <td data-label="专属邮箱">${escapeHtml(u.email || '未挂载')}</td>
      <td data-label="状态">${u.disabled ? '<span style="color:#ef4444;font-weight:500;">❌ 封禁</span>' : '<span style="color:#22c55e;font-weight:500;">✅ 正常</span>'}</td>
      <td data-label="管理">
        <button class="btn" style="padding:6px 12px; background:#f1f5f9; color:#0f172a; font-size:13px; border:1px solid #cbd5e1;" 
                onclick="editUser(${JSON.stringify(u).replace(/"/g, '&quot;')})">可视化配置</button>
      </td>
    </tr>
  `).join('');

  const checkboxHtml = AVAILABLE_PERMISSIONS.map(p => `
    <div class="perm-item">
      <label class="perm-label">
        <input type="checkbox" name="perms" value="${p.key}">
        <span><strong>${p.label}</strong> <code style="font-size:11px;color:#64748b;background:#f1f5f9;padding:1px 4px;border-radius:4px;">${p.key}</code></span>
      </label>
      <div class="perm-desc">${p.desc}</div>
    </div>
  `).join('');

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>用户授权管理</title>
  <style>${getCommonCss()}
    .m-card { background:#fff; padding:24px; border-radius:12px; margin-bottom:20px; display:none; border:1px solid #e2e8f0; box-shadow:0 4px 6px -1px rgba(0,0,0,0.05); }
    .f-grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:16px; }
    .perm-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin:12px 0 20px 0; background:#f8fafc; padding:16px; border-radius:8px; border:1px solid #e2e8f0; }
    .perm-item { background:#fff; padding:10px 12px; border-radius:6px; border:1px solid #e2e8f0; }
    .perm-label { display:flex; align-items:center; gap:8px; font-size:14px; color:#0f172a; cursor:pointer; }
    .perm-label input { width:16px; height:16px; cursor:pointer; }
    .perm-desc { font-size:12px; color:#64748b; margin-top:4px; padding-left:24px; }
    .tpl-btn { padding:4px 8px; background:#f1f5f9; border:1px solid #cbd5e1; border-radius:4px; font-size:12px; cursor:pointer; color:#475569; margin-right:6px; }
    .tpl-btn:hover { background:#e2e8f0; color:#0f172a; }
    @media(max-width:768px){ .f-grid, .perm-grid { grid-template-columns:1fr; } thead { display:none; } tr { display:block; background:#fff; border-radius:8px; margin-bottom:12px; padding:12px; box-shadow:0 1px 2px rgba(0,0,0,0.05);} td { display:flex; justify-content:space-between; padding:8px 0; border:none; text-align:right;} td::before { content:attr(data-label); color:#64748b; font-weight:500; } }
  </style></head>
  <body>
    <div class="container">
      ${getHeaderNav(session)}
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
        <h3 style="font-size:16px; font-weight:700;">👤 系统授权用户体系</h3>
        <button class="btn" onclick="showCreateForm()">+ 新增分配用户</button>
      </div>

      <div class="m-card" id="formCard">
        <h4 id="fTitle" style="margin-bottom:16px; font-size:15px; font-weight:700; border-bottom:2px solid #3b82f6; display:inline-block; padding-bottom:4px;">新增账号</h4>
        <form id="uForm">
          <input type="hidden" id="userId">
          <div class="f-grid">
            <div><label style="display:block;margin-bottom:6px;font-size:13px;font-weight:500;">登录用户名</label><input type="text" id="uName" style="width:100%; padding:10px; border:1px solid #cbd5e1; border-radius:6px;" required></div>
            <div><label style="display:block;margin-bottom:6px;font-size:13px;font-weight:500;">安全密码 <span id="pwdHint" style="color:#64748b;font-weight:400;"></span></label><input type="password" id="uPass" style="width:100%; padding:10px; border:1px solid #cbd5e1; border-radius:6px;"></div>
          </div>
          <div class="f-grid">
            <div><label style="display:block;margin-bottom:6px;font-size:13px;font-weight:500;">业务角色级别</label>
              <select id="uRole" style="width:100%; padding:10px; border:1px solid #cbd5e1; border-radius:6px;">
                <option value="user">普通用户 (USER)</option>
                <option value="admin">管理员 (ADMIN)</option>
              </select>
            </div>
            <div><label style="display:block;margin-bottom:6px;font-size:13px;font-weight:500;">专属绑定收件箱</label><input type="text" id="uEmail" placeholder="例如: alice@yourdomain.com" style="width:100%; padding:10px; border:1px solid #cbd5e1; border-radius:6px;"></div>
          </div>
          
          <div style="margin-top:16px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <label style="font-size:14px; font-weight:600; color:#0f172a;">🛡️ 业务功能权限细粒度分配</label>
              <div>
                <button type="button" class="tpl-btn" onclick="applyTemplate('user')">套用普通模板</button>
                <button type="button" class="tpl-btn" onclick="applyTemplate('admin')">套用管理模板</button>
              </div>
            </div>
            <div class="perm-grid">${checkboxHtml}</div>
          </div>

          <div class="g" style="margin-bottom:16px;">
            <label style="display:block;margin-bottom:6px;font-size:13px;font-weight:500;">允许穿透查看的具体箱/域名白名单 (一行一个)</label>
            <textarea id="uAccess" style="width:100%; height:80px; padding:10px; border:1px solid #cbd5e1; border-radius:6px; font-family:monospace;" placeholder="example@test.com&#10;@specdomain.com"></textarea>
          </div>
          <div class="g" style="margin-bottom:20px; background:#fff1f2; padding:10px; border-radius:6px; border:1px solid #ffe4e6;">
            <label style="cursor:pointer; font-weight:500; color:#991b1b; font-size:14px;"><input type="checkbox" id="uDisabled" style="margin-right:6px; width:15px; height:15px; vertical-align:middle;"> 临时全面封禁此账户</label>
          </div>
          
          <div style="display:flex; gap:10px;">
            <button type="submit" class="btn">保存策略</button>
            <button type="button" class="btn" style="background:#64748b;" onclick="hideForm()">放弃返回</button>
            <button type="button" id="delBtn" class="btn" style="background:#ef4444; margin-left:auto; display:none;" onclick="deleteUser()">彻底注销账户</button>
          </div>
        </form>
      </div>

      <div class="wrapper" style="overflow-x:auto;">
        <table>
          <thead><tr><th>用户名</th><th>业务角色</th><th>绑定的专属箱</th><th>当前状态</th><th>操作管理</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="5" style="text-align:center;color:#94a3b8;">暂无分配的用户。</td></tr>'}</tbody>
        </table>
      </div>
    </div>
    <script>
      let currentAction = 'create';
      function applyTemplate(role) {
        const checkboxes = document.querySelectorAll('input[name="perms"]');
        checkboxes.forEach(cb => cb.checked = false);
        const tplMap = {
          user: ['mail:view:own', 'mail:delete:own'],
          admin: ['mail:view:all', 'mail:delete:all', 'user:manage:restricted', 'log:view:all', 'system:config:view']
        };
        if (tplMap[role]) {
          tplMap[role].forEach(perm => {
            const el = document.querySelector('input[name="perms"][value="'+perm+'"]');
            if(el) el.checked = true;
          });
        }
      }
      function showCreateForm() {
        currentAction = 'create';
        document.getElementById('fTitle').innerText = '新增策略授权账号';
        document.getElementById('userId').value = '';
        document.getElementById('uName').value = ''; document.getElementById('uName').disabled = false;
        document.getElementById('uPass').required = true;
        document.getElementById('pwdHint').innerText = '(必需项)';
        document.getElementById('uEmail').value = '';
        document.getElementById('uRole').value = 'user';
        document.getElementById('uAccess').value = '';
        document.getElementById('uDisabled').checked = false;
        applyTemplate('user');
        document.getElementById('delBtn').style.display = 'none';
        document.getElementById('formCard').style.display = 'block';
        document.getElementById('formCard').scrollIntoView({ behavior: 'smooth' });
      }
      function editUser(u) {
        currentAction = 'update';
        document.getElementById('fTitle').innerText = '修改账户授权 - ' + u.username;
        document.getElementById('userId').value = u.id;
        document.getElementById('uName').value = u.username; document.getElementById('uName').disabled = true;
        document.getElementById('uPass').required = false;
        document.getElementById('pwdHint').innerText = '(留空代表维持原密码)';
        document.getElementById('uEmail').value = u.email || '';
        document.getElementById('uRole').value = u.role;
        document.getElementById('uDisabled').checked = u.disabled === 1;
        const checkboxes = document.querySelectorAll('input[name="perms"]');
        checkboxes.forEach(cb => { cb.checked = u.permissions.includes(cb.value); });
        document.getElementById('uAccess').value = (u.accessible_emails || []).join('\\n');
        document.getElementById('delBtn').style.display = 'inline-block';
        document.getElementById('formCard').style.display = 'block';
        document.getElementById('formCard').scrollIntoView({ behavior: 'smooth' });
      }
      function hideForm() { document.getElementById('formCard').style.display = 'none'; }
      document.getElementById('uForm').onsubmit = async (e) => {
        e.preventDefault();
        const checkedPerms = Array.from(document.querySelectorAll('input[name="perms"]:checked')).map(cb => cb.value);
        const accessEmails = document.getElementById('uAccess').value.split('\\n').map(line => line.trim()).filter(Boolean);
        const body = {
          action: currentAction,
          id: document.getElementById('userId').value,
          username: document.getElementById('uName').value,
          password: document.getElementById('uPass').value,
          email: document.getElementById('uEmail').value,
          role: document.getElementById('uRole').value,
          permissions: checkedPerms,
          accessible_emails: accessEmails,
          disabled: document.getElementById('uDisabled').checked
        };
        const res = await fetch('/admin/users', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
        if(res.ok) { location.reload(); } else { const d = await res.json(); alert('配置同步失败: ' + d.message); }
      };
      async function deleteUser() {
        if(confirm('确定要注销删除该用户账户吗？')) {
          const body = { action: 'delete', id: document.getElementById('userId').value };
          const res = await fetch('/admin/users', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
          if(res.ok) location.reload(); else alert('注销失败，权限不足');
        }
      }
    </script>
  </body></html>`;
}

function generateLogPage(logs, session) {
  // 🔥 根据用户的精确需求，匹配操作分类与 UI 高亮颜色
  const getActionTag = (action) => {
    const map = {
      'login': { tag: '系统', color: '#6366f1' },
      'logout': { tag: '系统', color: '#6366f1' },
      'update_system_config': { tag: '系统', color: '#6366f1' },
      'view_message': { tag: '邮件', color: '#3b82f6' },
      'delete_message': { tag: '邮件', color: '#3b82f6' },
      'create_user': { tag: '管理', color: '#f59e0b' },
      'update_user': { tag: '管理', color: '#f59e0b' },
      'delete_user': { tag: '管理', color: '#f59e0b' },
      'update_permission': { tag: '权限', color: '#8b5cf6' },
      'view_logs': { tag: '日志', color: '#10b981' },
      'access_denied': { tag: '安全', color: '#ef4444' }
    };
    return map[action] || { tag: '其他', color: '#64748b' };
  };

  const rows = logs.map(l => {
    const details = JSON.parse(l.details);
    const meta = getActionTag(l.action);
    const resultStr = l.success ? '<span style="color:#22c55e;font-weight:600;">成功</span>' : '<span style="color:#ef4444;font-weight:600;">失败</span>';
    
    // 完全符合： {标签} {用户名}（{ip}）执行 xxxxx 操作 - 结果 ：{} 
    return `
      <div style="padding:16px; border-bottom:1px solid #e2e8f0; display:flex; flex-wrap:wrap; align-items:flex-start; gap:12px;">
        <div style="font-size:13px; color:#64748b; min-width:145px; font-family:monospace;">${new Date(l.created_at).toLocaleString('zh-CN')}</div>
        <div style="font-size:14px; color:#1e293b; flex:1; line-height:1.6;">
          <strong style="color:${meta.color}; margin-right:4px;">[${meta.tag}]</strong>
          <strong style="font-size:15px;">${escapeHtml(l.username)}</strong>
          <span style="color:#64748b;">（${escapeHtml(l.ip)}）</span>
          执行 <span style="background:#f1f5f9; padding:2px 6px; border-radius:4px; font-weight:500;">${escapeHtml(details.description)}</span> 操作 
          - 结果：${resultStr}
        </div>
      </div>
    `;
  }).join('');

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>集中审计日志</title>
  <style>${getCommonCss()}</style></head>
  <body>
    <div class="container">
      ${getHeaderNav(session)}
      <div class="wrapper" style="padding:8px 0;">
        <div style="padding:16px 20px; border-bottom:2px solid #f1f5f9; background:#f8fafc; border-radius:12px 12px 0 0;">
          <h3 style="font-size:16px; font-weight:700; margin:0;">📋 实时系统底层审计日志</h3>
        </div>
        ${rows || '<div style="padding:40px; text-align:center; color:#94a3b8;">系统崭新，暂无任何日志记录。</div>'}
      </div>
    </div>
  </body></html>`;
}

function generateSettingsPage(config, session) {
  const isReadonly = session.role !== 'superuser' && !session.permissions.includes('system:config:edit');
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>系统核心配置</title>
  <style>${getCommonCss()}
    .box { background:#fff; padding:24px; border-radius:12px; box-shadow:0 1px 3px rgba(0,0,0,0.05); max-width:600px; margin:0 auto; }
  </style></head>
  <body>
    <div class="container">
      ${getHeaderNav(session)}
      <div class="box">
        <h3 style="margin-bottom:16px; font-size:16px;">⚙️ 全局核心设置策略面板</h3>
        <form id="sForm">
          <div class="g" style="margin-bottom:16px;">
            <label style="display:block; font-weight:500; margin-bottom:6px;">允许接收邮件的域名后缀白名单（一行一个，留空不限制）</label>
            <textarea id="domains" style="width:100%; height:100px; padding:10px; border:1px solid #cbd5e1; border-radius:6px;" ${isReadonly?'disabled':''}>${(config.allowed_domains || []).join('\n')}</textarea>
          </div>
          <div class="g" style="margin-bottom:20px;">
            <label style="display:block; font-weight:500; margin-bottom:6px;">登录凭证 JWT 有效租期 (小时)</label>
            <input type="number" id="expiry" value="${config.session_expiry_hours || 24}" style="width:100%; padding:10px; border:1px solid #cbd5e1; border-radius:6px;" ${isReadonly?'disabled':''}>
          </div>
          ${isReadonly ? '<p style="color:#ef4444;font-size:13px;">您当前持有的安全角色仅允许查阅，无修改权限。</p>' : '<button type="submit" class="btn">持久化应用并刷新热重载</button>'}
        </form>
      </div>
    </div>
    <script>
      if(document.getElementById('sForm')) {
        document.getElementById('sForm').onsubmit = async (e) => {
          e.preventDefault();
          const body = {
            allowed_domains: document.getElementById('domains').value.split('\n').map(d=>d.trim()).filter(Boolean),
            session_expiry_hours: parseInt(document.getElementById('expiry').value, 10)
          };
          const res = await fetch('/admin/settings', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
          if(res.ok) alert('修改成功，系统已执行配置无感热重载！'); else alert('执行失败');
        }
      }
    </script>
  </body></html>`;
}

function getCommonCss() {
  return `
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; background-color:#f8fafc; color:#1e293b; padding:16px; }
    .container { max-width:1200px; margin:0 auto; }
    .header { display:flex; justify-content:space-between; align-items:center; background:#fff; padding:14px 20px; border-radius:12px; box-shadow:0 1px 3px rgba(0,0,0,0.05); margin-bottom:12px; }
    .nav-brand { font-size:16px; font-weight:700; }
    .nav-links { display:flex; gap:14px; align-items:center; }
    .nav-item { color:#475569; text-decoration:none; font-size:14px; font-weight:500; }
    .nav-item:hover { color:#0f172a; }
    .user-badge { font-size:12px; color:#64748b; margin-bottom:16px; padding-left:4px; }
    .wrapper { background:#fff; border-radius:12px; box-shadow:0 1px 3px rgba(0,0,0,0.05); }
    table { width:100%; border-collapse:collapse; font-size:14px; text-align:left; }
    th { background:#f8fafc; padding:14px 16px; font-weight:600; color:#64748b; border-bottom:1px solid #e2e8f0; }
    td { padding:14px 16px; border-bottom:1px solid #f1f5f9; color:#334155; vertical-align:middle; }
    tr:hover { background-color:#f8fafc; }
    tr.unread { background-color:#f0fdf4; }
    .link { color:#2563eb; text-decoration:none; font-weight:500; }
    .link:hover { text-decoration:underline; }
    .badge { padding:4px 8px; border-radius:4px; font-size:11px; font-weight:600; }
    .badge-unread { background:#dcfce7; color:#166534; }
    .badge-read { background:#f1f5f9; color:#64748b; }
    .btn { padding:10px 16px; background:#2563eb; color:#fff; border:none; border-radius:6px; font-size:14px; font-weight:500; cursor:pointer; }
    .btn:hover { background:#1d4ed8; }
    .logout-btn { padding:6px 12px; background:#fee2e2; color:#ef4444; text-decoration:none; border-radius:6px; font-size:13px; font-weight:600; }
    .logout-btn:hover { background:#ef4444; color:#fff; }
    .del-btn { padding:6px 12px; background:#fff; color:#ef4444; border:1px solid #fee2e2; border-radius:6px; cursor:pointer; font-size:12px; transition:0.2s; }
    .del-btn:hover { background:#ef4444; color:#fff; }
  `;
}

function escapeHtml(unsafe) {
  if (!unsafe) return '';
  return String(unsafe)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
