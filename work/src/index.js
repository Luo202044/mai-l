import PostalMime from 'postal-mime';

// ==========================================
// 1. 数据库初始化 SQL
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

let tablesReady = false;

export default {
  // 📥 邮件接收处理逻辑 (已移除废弃的白名单拦截)
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
        `INSERT INTO messages (mailbox_id, from_address, subject, content, html_content) VALUES (?, ?, ?, ?, ?)`
      ).bind(mailbox.id, parsedEmail.from?.address || 'Unknown', parsedEmail.subject || '(无主题)',
        parsedEmail.text || parsedEmail.html || '(无内容)', parsedEmail.html || null).run();
    } catch (error) { console.error('❌ 处理邮件失败:', error); }
  },

  async fetch(request, env, ctx) {
    await ensureTables(env);
    const url = new URL(request.url);
    const path = url.pathname;
    
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
      } catch (e) { return null; }
    };

    const getSession = async () => {
      const cookies = parseCookies(request.headers.get('Cookie') || '');
      if (!cookies.auth_token) return null;
      const payload = await verifyJWT(cookies.auth_token);
      if (!payload) return null;
      if (payload.user_id === 0) return payload;

      const dbUser = await env.DB.prepare('SELECT token_version, disabled, permissions, accessible_emails FROM users WHERE id = ?').bind(payload.user_id).first();
      if (!dbUser || dbUser.disabled === 1 || dbUser.token_version !== payload.token_version) return null; 

      payload.permissions = JSON.parse(dbUser.permissions || '[]');
      payload.accessible_emails = JSON.parse(dbUser.accessible_emails || '[]');
      return payload;
    };

    const logAction = async (userId, username, action, targetType, targetId, description, success) => {
      try {
        await env.DB.prepare(`INSERT INTO audit_logs (user_id, username, action, target_type, target_id, details, ip, user_agent, success) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(userId, username, action, targetType, targetId ? String(targetId) : null, JSON.stringify({ description }), clientIp, userAgent, success ? 1 : 0).run();
      } catch (e) {}
    };

    // --- API: 用户修改自身密码 ---
    if (path === '/api/change-password' && request.method === 'POST') {
      const session = await getSession();
      if (!session) return new Response(null, { status: 401 });
      const config = await getSystemConfig(env);
      if (session.role === 'superuser') return new Response(JSON.stringify({message: '超管账户不支持在此修改密码'}), {status: 403});
      if (!config.allow_user_change_password) return new Response(JSON.stringify({message: '系统禁止用户修改密码'}), {status: 403});

      const { oldPwd, newPwd } = await request.json();
      const user = await env.DB.prepare('SELECT password_hash FROM users WHERE id = ?').bind(session.user_id).first();
      const oldHash = await hashPassword(oldPwd);
      if (oldHash !== user.password_hash) return new Response(JSON.stringify({message: '当前密码错误'}), {status: 401});
      
      const newHash = await hashPassword(newPwd);
      await env.DB.prepare('UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE id = ?').bind(newHash, session.user_id).run();
      await logAction(session.user_id, session.username, 'update_user', 'user', session.user_id, '用户修改自身密码', true);
      return new Response(JSON.stringify({success: true}));
    }

    if (path === '/profile' && request.method === 'GET') {
      const session = await getSession();
      if (!session) return new Response(null, { status: 302, headers: { 'Location': '/login' } });
      const config = await getSystemConfig(env);
      return new Response(generateProfilePage(session, config), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    // --- 登录系统 (含限流与黑名单验证) ---
    if (path === '/api/login' && request.method === 'POST') {
      try {
        const formData = await request.formData();
        const username = formData.get('username') || '';
        const password = formData.get('password') || '';
        const config = await getSystemConfig(env);
        const expiryHours = config.session_expiry_hours || 24;

        if (config.ip_blacklist) {
          const bl = config.ip_blacklist.split(';').map(ip => ip.trim()).filter(Boolean);
          if (bl.includes(clientIp)) {
            await logAction(-1, username, 'login', 'user', null, '触发黑名单IP阻断', false);
            return new Response(JSON.stringify({ success: false, message: '当前 IP 已被管理员列入黑名单，禁止登录。' }), { status: 403 });
          }
        }

        if (env.CONFIG_KV) {
          const isLocked = await env.CONFIG_KV.get(`lockout:${clientIp}`);
          if (isLocked) {
             await logAction(-1, username, 'login', 'user', null, '触发IP频繁失败安全锁定拦截', false);
             return new Response(JSON.stringify({ success: false, message: '失败次数过多，该 IP 已被限制登录请稍后再试。' }), { status: 429 });
          }
        }

        let isSuccess = false; let userId = -1; let userRole = ''; let userPerms = []; let tokenVer = 0;

        if (username === SUPER_USER && password === SUPER_PASS) {
          isSuccess = true; userId = 0; userRole = 'superuser'; userPerms = ['*']; tokenVer = 0;
        } else {
          const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
          if (user) {
            if (user.disabled === 1) {
              await logAction(user.id, username, 'login', 'user', user.id, '系统登录（账户封禁）', false);
              return new Response(JSON.stringify({ success: false, message: '账户已被封禁' }), { status: 403 });
            }
            const inputHash = await hashPassword(password);
            if (inputHash === user.password_hash) {
              isSuccess = true; userId = user.id; userRole = user.role; userPerms = JSON.parse(user.permissions || '[]'); tokenVer = user.token_version;
            }
          }
        }

        if (isSuccess) {
          if (env.CONFIG_KV) await env.CONFIG_KV.delete(`fails:${clientIp}`); 
          const jwt = await generateJWT({ user_id: userId, username, role: userRole, permissions: userPerms, token_version: tokenVer, exp: Date.now() + (expiryHours * 60 * 60 * 1000) });
          await logAction(userId, username, 'login', 'user', userId, '系统登录', true);
          return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json', 'Set-Cookie': `auth_token=${jwt}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${expiryHours * 3600}` } });
        } else {
          if (env.CONFIG_KV) {
            const failKey = `fails:${clientIp}`;
            let fails = parseInt((await env.CONFIG_KV.get(failKey)) || '0') + 1;
            const windowSecs = Math.max(60, (config.failure_window_hours || 1) * 3600);
            await env.CONFIG_KV.put(failKey, fails.toString(), { expirationTtl: windowSecs });
            if (fails >= (config.max_login_failures || 5)) {
              const lockoutSecs = Math.max(60, (config.lockout_hours || 2) * 3600);
              await env.CONFIG_KV.put(`lockout:${clientIp}`, '1', { expirationTtl: lockoutSecs });
              await env.CONFIG_KV.delete(failKey);
            }
          }
          await logAction(-1, username, 'login', 'user', null, '系统登录（密码错误）', false);
          return new Response(JSON.stringify({ success: false, message: '用户名或密码错误' }), { status: 401 });
        }
      } catch (e) { return new Response(JSON.stringify({ success: false, message: e.message }), { status: 500 }); }
    }

    if (path === '/login' && request.method === 'GET') {
      return new Response(generateLoginPage(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }
    if (path === '/logout') {
      const session = await getSession();
      if (session) await logAction(session.user_id, session.username, 'logout', 'user', session.user_id, '注销退出系统', true);
      return new Response(null, { status: 302, headers: { 'Location': '/login', 'Set-Cookie': 'auth_token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0' }});
    }

    // 🛡️ JWT 全局鉴权卡点
    const session = await getSession();
    if (!session) return new Response(null, { status: 302, headers: { 'Location': '/login' } });
    const hasPermission = (perm) => session.role === 'superuser' || session.permissions.includes(perm);

    // --- 邮件首页 ---
    if (path === '/' || path === '') {
      try {
        const page = parseInt(url.searchParams.get('page')) || 1;
        const size = parseInt(url.searchParams.get('size')) || 20;
        const offset = (page - 1) * size;
        let baseSql = `FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id`;
        let conditions = []; let bindParams = [];

        if (session.role !== 'superuser' && !hasPermission('mail:view:all')) {
          if (session.accessible_emails && session.accessible_emails.length > 0) {
            session.accessible_emails.forEach(allowed => {
              if (allowed.startsWith('@')) { conditions.push(`mb.email LIKE ?`); bindParams.push(`%${allowed}`); } 
              else { conditions.push(`mb.email = ?`); bindParams.push(allowed); }
            });
          } else {
            return new Response(generateListPage([], session, 1, 0), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
          }
        }
        let whereClause = conditions.length > 0 ? ` WHERE ${conditions.join(' OR ')}` : '';
        const countStmt = env.DB.prepare(`SELECT COUNT(*) as total ${baseSql} ${whereClause}`);
        const countRes = await (bindParams.length > 0 ? countStmt.bind(...bindParams) : countStmt).first();
        const totalPages = Math.ceil(countRes.total / size);

        const dataStmt = env.DB.prepare(`SELECT m.*, mb.email as mailbox_email ${baseSql} ${whereClause} ORDER BY m.received_at DESC LIMIT ? OFFSET ?`);
        const messages = await dataStmt.bind(...bindParams, size, offset).all();
        return new Response(generateListPage(messages.results, session, page, totalPages), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      } catch (e) { return new Response('系统错误: ' + e.message, { status: 500 }); }
    }

    if (path.startsWith('/view/')) {
      const messageId = path.split('/')[2];
      try {
        const message = await env.DB.prepare(`SELECT m.*, mb.email as mailbox_email FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id WHERE m.id = ?`).bind(messageId).first();
        if (!message) return new Response('邮件不存在', { status: 404 });
        if (!checkMailAccess(session, message.mailbox_email, 'view')) return new Response('无权查看该邮件', { status: 403 });
        await env.DB.prepare('UPDATE messages SET is_read = 1 WHERE id = ?').bind(messageId).run();
        await logAction(session.user_id, session.username, 'view_message', 'message', messageId, `查看邮件`, true);
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

    if (path === '/api/batch-delete/messages' && request.method === 'POST') {
      const { ids } = await request.json();
      if (!Array.isArray(ids) || ids.length === 0) return new Response('Bad Request', { status: 400 });
      const placeholders = ids.map(() => '?').join(',');
      const msgs = await env.DB.prepare(`SELECT m.id, mb.email FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id WHERE m.id IN (${placeholders})`).bind(...ids).all();
      const authorizedIds = msgs.results.filter(m => checkMailAccess(session, m.email, 'delete')).map(m => m.id);
      if (authorizedIds.length > 0) {
         const delPlaceholders = authorizedIds.map(() => '?').join(',');
         await env.DB.prepare(`DELETE FROM messages WHERE id IN (${delPlaceholders})`).bind(...authorizedIds).run();
         await logAction(session.user_id, session.username, 'delete_message', 'message', null, `执行 批量删除 类型（邮件），共 ${authorizedIds.length} 条`, true);
      }
      return new Response(JSON.stringify({ success: true, count: authorizedIds.length }));
    }

    if (path.startsWith('/api/users/') && path.endsWith('/logs') && request.method === 'GET') {
      if (!hasPermission('user:manage:restricted') && !hasPermission('user:manage:all')) return new Response('Forbidden', {status: 403});
      const targetId = path.split('/')[3];
      const logs = await env.DB.prepare('SELECT * FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 50').bind(targetId).all();
      return new Response(JSON.stringify({logs: logs.results}), {headers:{'Content-Type':'application/json'}});
    }

    // --- 用户管理系统 ---
    if (path === '/admin/users') {
      if (!hasPermission('user:manage:restricted') && !hasPermission('user:manage:all')) return new Response('无权访问管理面板', { status: 403 });

      if (request.method === 'GET') {
        const page = parseInt(url.searchParams.get('page')) || 1;
        const size = parseInt(url.searchParams.get('size')) || 20;
        const offset = (page - 1) * size;
        const countRes = await env.DB.prepare('SELECT COUNT(*) as total FROM users').first();
        const totalPages = Math.ceil(countRes.total / size);
        const users = await env.DB.prepare('SELECT id, username, role, permissions, accessible_emails, disabled, created_at FROM users ORDER BY id DESC LIMIT ? OFFSET ?').bind(size, offset).all();
        
        const parsedUsers = users.results.map(u => {
          let perms = [], emails = [];
          try { perms = JSON.parse(u.permissions || '[]'); } catch (e) {}
          try { emails = JSON.parse(u.accessible_emails || '[]'); } catch (e) {}
          return { ...u, permissions: perms, accessible_emails: emails };
        });
        return new Response(generateUserPage(parsedUsers, session, page, totalPages), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }

      if (request.method === 'POST') {
        try {
          const body = await request.json();
          const { action, id, username, password, role, permissions, accessible_emails, disabled } = body;
          if (!hasPermission('user:manage:all') && role === 'admin') return new Response(JSON.stringify({ success: false, message: '您无权管理管理员账户' }), { status: 403 });

          if (action === 'create') {
            const pwdHash = await hashPassword(password);
            await env.DB.prepare(`INSERT INTO users (username, password_hash, role, permissions, accessible_emails, created_by) VALUES (?, ?, ?, ?, ?, ?)`).bind(username, pwdHash, role, JSON.stringify(permissions), JSON.stringify(accessible_emails), session.user_id).run();
            await logAction(session.user_id, session.username, 'create_user', 'user', null, `新增系统账户: ${username} [${role}]`, true);
            return new Response(JSON.stringify({ success: true }));
          }

          if (action === 'update') {
            const target = await env.DB.prepare('SELECT role, permissions, accessible_emails FROM users WHERE id = ?').bind(id).first();
            if (target.role === 'admin' && !hasPermission('user:manage:all')) return new Response(JSON.stringify({ success: false, message: '权限不足，无法编辑高管' }), { status: 403 });

            let updateSql = `UPDATE users SET role = ?, permissions = ?, accessible_emails = ?, disabled = ?, token_version = token_version + 1`;
            let params = [role, JSON.stringify(permissions), JSON.stringify(accessible_emails), disabled ? 1 : 0];
            if (password && password.trim() !== '') {
              const newHash = await hashPassword(password);
              updateSql += `, password_hash = ?`; params.push(newHash);
            }
            updateSql += ` WHERE id = ?`; params.push(id);
            await env.DB.prepare(updateSql).bind(...params).run();
            
            await logAction(session.user_id, session.username, 'update_user', 'user', id, `编辑基本账户信息: ${username}`, true);
            if (target.permissions !== JSON.stringify(permissions) || target.accessible_emails !== JSON.stringify(accessible_emails)) {
              await logAction(session.user_id, session.username, 'update_permission', 'user', id, `更改了权限清单或可视邮箱白名单: ${username}`, true);
            }
            return new Response(JSON.stringify({ success: true }));
          }

          if (action === 'delete') {
            if (!hasPermission('user:manage:all')) return new Response(JSON.stringify({ success: false, message: '权限不足' }), { status: 403 });
            await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
            await logAction(session.user_id, session.username, 'delete_user', 'user', id, `注销删除了账户 ID: ${id}`, true);
            return new Response(JSON.stringify({ success: true }));
          }
        } catch (e) { return new Response(JSON.stringify({ success: false, message: e.message }), { status: 500 }); }
      }
    }

    // --- 日志管理页 ---
    if (path === '/admin/logs' && hasPermission('log:view:all')) {
      const page = parseInt(url.searchParams.get('page')) || 1;
      const size = parseInt(url.searchParams.get('size')) || 20;
      const offset = (page - 1) * size;
      const countRes = await env.DB.prepare('SELECT COUNT(*) as total FROM audit_logs').first();
      const totalPages = Math.ceil(countRes.total / size);
      const logs = await env.DB.prepare('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ? OFFSET ?').bind(size, offset).all();
      return new Response(generateLogPage(logs.results, session, page, totalPages), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    // 🧹 API: 全量过期日志清理
    if (path === '/admin/logs/cleanup' && request.method === 'POST') {
      if (session.role !== 'superuser') return new Response(JSON.stringify({ success: false, message: '仅超级管理员可执行日志清理' }), { status: 403 });
      try {
        const config = await getSystemConfig(env);
        const days = config.log_retention_days || 30;
        const result = await env.DB.prepare("DELETE FROM audit_logs WHERE created_at < datetime('now', ?)").bind(`-${days} days`).run();
        await logAction(session.user_id, session.username, 'cleanup_logs', 'log', null, `执行清理过期日志（保留 ${days} 天），共抹除 ${result.meta.changes} 条`, true);
        return new Response(JSON.stringify({ success: true, count: result.meta.changes }), { headers: { 'Content-Type': 'application/json' } });
      } catch (e) { return new Response(JSON.stringify({ success: false, message: e.message }), { status: 500 }); }
    }

    // ❌ API: 可选删除特定单一日志
    if (path.startsWith('/admin/logs/delete/') && request.method === 'POST') {
      if (session.role !== 'superuser') return new Response(JSON.stringify({ success: false, message: '越权操作' }), { status: 403 });
      const logId = path.split('/')[4];
      try {
        await env.DB.prepare("DELETE FROM audit_logs WHERE id = ?").bind(logId).run();
        return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
      } catch (e) { return new Response(JSON.stringify({ success: false, message: e.message }), { status: 500 }); }
    }

    // ❌ API: 批量删除日志
    if (path === '/api/batch-delete/logs' && request.method === 'POST') {
      if (session.role !== 'superuser') return new Response('Forbidden', {status:403});
      const { ids } = await request.json();
      if (!Array.isArray(ids) || ids.length === 0) return new Response('Bad Request', { status: 400 });
      const placeholders = ids.map(() => '?').join(',');
      await env.DB.prepare(`DELETE FROM audit_logs WHERE id IN (${placeholders})`).bind(...ids).run();
      await logAction(session.user_id, session.username, 'delete_message', 'log', null, `执行 批量删除 类型（日志），共粉碎 ${ids.length} 条轨迹`, true);
      return new Response(JSON.stringify({ success: true }));
    }

    // --- 系统核心设置 (已彻底修复更新失效Bug，采用全网强制覆盖同步) ---
    if (path === '/admin/settings' && hasPermission('system:config:view')) {
      if (request.method === 'GET') {
        const config = await getSystemConfig(env);
        return new Response(generateSettingsPage(config, session), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }
      
      if (request.method === 'POST' && hasPermission('system:config:edit')) {
        try {
          const body = await request.json();
          // 【核心修复】：利用 D1 的 UPSERT 原子级并发覆盖机制，直接写入最新配置值
          const updateConfig = async (key, val) => {
             await env.DB.prepare(`INSERT INTO system_config (key, value, updated_by, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_by=excluded.updated_by, updated_at=CURRENT_TIMESTAMP`).bind(key, JSON.stringify(val), session.user_id).run();
          };

          await updateConfig('session_expiry_hours', parseInt(body.session_expiry_hours, 10) || 24);
          await updateConfig('log_retention_days', parseInt(body.log_retention_days, 10) || 30);
          await updateConfig('max_login_failures', parseInt(body.max_login_failures, 10) || 5);
          await updateConfig('failure_window_hours', parseInt(body.failure_window_hours, 10) || 1);
          await updateConfig('lockout_hours', parseInt(body.lockout_hours, 10) || 2);
          await updateConfig('ip_blacklist', body.ip_blacklist || "");
          await updateConfig('allow_user_change_password', !!body.allow_user_change_password);

          await logAction(session.user_id, session.username, 'update_system_config', 'system_config', null, '重新编排下发了系统环境变量', true);
          return new Response(JSON.stringify({ success: true }));
        } catch (e) { return new Response(JSON.stringify({ success: false, message: e.message }), { status: 500 }); }
      }
    }

    return new Response('Not Found', { status: 404 });
  }
};

// ==========================================
// 3. 策略校验与核心配置提取
// ==========================================
function checkMailAccess(session, targetEmail, type) {
  if (session.role === 'superuser' || session.permissions.includes(`mail:${type}:all`)) return true;
  if (session.permissions.includes(`mail:${type}:allowed`) || session.permissions.includes(`mail:${type}:own`)) {
    if (!session.accessible_emails) return false;
    return session.accessible_emails.some(allowed => {
      if (allowed.startsWith('@')) return targetEmail.endsWith(allowed);
      return allowed === targetEmail;
    });
  }
  return false;
}

// 【核心修复】：彻底废弃不稳定的 60 秒全局隔离内存，直接高速透穿查询 D1。保证所有修改刷新即刻生效！
async function getSystemConfig(env) {
  const rows = await env.DB.prepare('SELECT key, value FROM system_config').all();
  const config = { log_retention_days: 30, session_expiry_hours: 24, max_login_failures: 5, failure_window_hours: 1, lockout_hours: 2, ip_blacklist: "", allow_user_change_password: true };
  rows.results.forEach(row => { 
    try { config[row.key] = JSON.parse(row.value); } 
    catch(e) { config[row.key] = row.value; } 
  });
  return config;
}

async function ensureTables(env) {
  if (tablesReady) return;
  try { await env.DB.exec(CREATE_TABLES_SQL); tablesReady = true; } catch (err) {}
}

function parseCookies(header) {
  const cookies = {};
  if (header) { header.split(';').forEach(c => { const [name, value] = c.trim().split('='); if (name && value) cookies[name] = decodeURIComponent(value); }); }
  return cookies;
}

// ==========================================
// 4. 🎨 凡戴克棕 + 浅卡其色 UI 渲染引擎
// ==========================================
function getHeaderNav(session) {
  const hasUserManage = session.role === 'superuser' || session.permissions.includes('user:manage:restricted') || session.permissions.includes('user:manage:all');
  const hasLogs = session.role === 'superuser' || session.permissions.includes('log:view:all');
  const hasSettings = session.role === 'superuser' || session.permissions.includes('system:config:view');

  return `
    <div class="header">
      <div class="nav-brand"><a href="/">📬 邮件接收系统</a></div>
      <div class="nav-links">
        <a href="/" class="nav-item">列表</a>
        ${hasUserManage ? `<a href="/admin/users" class="nav-item">用户</a>` : ''}
        ${hasLogs ? `<a href="/admin/logs" class="nav-item">审计</a>` : ''}
        ${hasSettings ? `<a href="/admin/settings" class="nav-item">系统</a>` : ''}
        <a href="/profile" class="nav-item">账号</a>
        <a href="/logout" class="logout-btn">退出</a>
      </div>
    </div>
  `;
}

function generatePaginationHtml(page, totalPages, baseUrl) {
  if (totalPages <= 1) return '';
  let html = `<div style="display:flex; justify-content:center; align-items:center; gap:10px; padding: 16px;">`;
  if (page > 1) html += `<a href="${baseUrl}?page=${page - 1}" class="btn" style="background:var(--secondary); color:var(--primary);">上一页</a>`;
  html += `<span style="font-weight:600; color:var(--primary);">第 ${page} / ${totalPages} 页</span>`;
  if (page < totalPages) html += `<a href="${baseUrl}?page=${page + 1}" class="btn" style="background:var(--secondary); color:var(--primary);">下一页</a>`;
  html += `</div>`;
  return html;
}

function generateProfilePage(session, config) {
  const isSuper = session.role === 'superuser';
  const canChange = config.allow_user_change_password && !isSuper;

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>修改密码</title>
  <style>${getCommonCss()}
    .box { background:#fff; padding:24px; border-radius:12px; box-shadow:0 1px 3px rgba(0,0,0,0.05); max-width:500px; margin:0 auto; }
    .g { margin-bottom:16px; }
    .g label { display:block; margin-bottom:6px; font-weight:500; font-size:14px; }
    .g input { width:100%; padding:10px; border:1px solid var(--border); border-radius:6px; }
  </style></head>
  <body>
    <div class="container">
      ${getHeaderNav(session)}
      <div class="box">
        <h3 style="margin-bottom:16px; color:var(--primary);">🔒 账户安全设定</h3>
        ${isSuper ? '<p style="color:#ef4444; background:#fee2e2; padding:10px; border-radius:6px;">超管账户不支持在此修改密码。</p>' : ''}
        ${!isSuper && !config.allow_user_change_password ? '<p style="color:#ef4444; background:#fee2e2; padding:10px; border-radius:6px;">你当前账户权限或角色不支持更改密码。</p>' : ''}
        
        ${canChange ? `
        <form id="pwdForm">
          <div class="g"><label>当前密码</label><input type="password" id="oldPwd" required></div>
          <div class="g"><label>新密码</label><input type="password" id="newPwd" required></div>
          <div class="g"><label>确认新密码</label><input type="password" id="newPwd2" required></div>
          <button type="submit" class="btn" style="width:100%;">提交修改</button>
        </form>
        <script>
          document.getElementById('pwdForm').onsubmit = async (e) => {
             e.preventDefault();
             const o = document.getElementById('oldPwd').value;
             const n1 = document.getElementById('newPwd').value;
             const n2 = document.getElementById('newPwd2').value;
             if(n1 !== n2) return alert('两次新密码输入不一致');
             const res = await fetch('/api/change-password', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({oldPwd:o, newPwd:n1}) });
             if(res.ok) { alert('密码修改成功，系统将要求你重新登录。'); window.location.href='/logout'; }
             else { const d = await res.json(); alert(d.message); }
          }
        </script>
        ` : ''}
      </div>
    </div>
  </body></html>`;
}

function generateLoginPage() {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>安全认证登录</title>
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family:-apple-system,system-ui,sans-serif; background: #D8C7B5; min-height:100vh; display:flex; justify-content:center; align-items:center; padding:16px; color:#492D22; }
    .card { background:#fff; border-radius:16px; width:100%; max-width:360px; padding:32px 24px; box-shadow:0 10px 25px -5px rgba(0,0,0,0.1); border-top: 4px solid #492D22; }
    .h { text-align:center; margin-bottom:24px; }
    .h h2 { font-size:20px; color:#492D22; }
    .g { margin-bottom:16px; }
    .g label { display:block; margin-bottom:6px; color:#492D22; font-size:14px; font-weight:600; }
    .g input { width:100%; padding:12px; border:1px solid #D8C7B5; border-radius:8px; font-size:14px; }
    .g input:focus { outline:none; border-color:#492D22; }
    .btn { width:100%; padding:12px; background:#492D22; color:#fff; border:none; border-radius:8px; font-size:15px; font-weight:600; cursor:pointer; }
    .err { color:#ef4444; background:rgba(239,68,68,0.1); padding:10px; border-radius:6px; margin-bottom:16px; font-size:13px; display:none; }
  </style></head>
  <body>
    <div class="card">
      <div class="h"><h2>📧 邮件接收管理系统</h2></div>
      <div class="err" id="e"></div>
      <form id="f">
        <div class="g"><label>登录名</label><input type="text" id="u" required autofocus></div>
        <div class="g"><label>身份识别码</label><input type="password" id="p" required></div>
        <button type="submit" class="btn">核实验身</button>
      </form>
    </div>
    <script>
      document.getElementById('f').onsubmit = async (e) => {
        e.preventDefault();
        const err = document.getElementById('e'); err.style.display = 'none';
        const fd = new URLSearchParams(); fd.append('username', document.getElementById('u').value); fd.append('password', document.getElementById('p').value);
        const res = await fetch('/api/login', { method:'POST', body:fd });
        if(res.ok) { window.location.href = '/'; } 
        else { const data = await res.json(); err.innerText = data.message; err.style.display='block'; }
      }
    </script>
  </body></html>`;
}

function generateListPage(messages, session, page, totalPages) {
  const rows = messages.map(msg => `
    <tr>
      <td data-label="勾选"><input type="checkbox" class="batch-cb" value="${msg.id}"></td>
      <td data-label="收件邮箱" style="font-weight:600; color:var(--primary);">${escapeHtml(msg.mailbox_email)}</td>
      <td data-label="发件人">${escapeHtml(msg.from_address)}</td>
      <td data-label="邮件主题"><a class="link" href="/view/${msg.id}">${msg.is_read ? '' : '✉️ '}${escapeHtml(msg.subject || '(无主题)')}</a></td>
      <td data-label="到达时间" style="color:#666;font-size:13px;">${new Date(msg.received_at).toLocaleString('zh-CN')}</td>
    </tr>
  `).join('');

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>邮件收件箱</title>
  <style>${getCommonCss()}
    @media(max-width:768px){
      thead{display:none;} tr{display:block; background:#fff; border-radius:8px; margin-bottom:12px; padding:12px; box-shadow:0 1px 2px rgba(0,0,0,0.05);}
      td{display:flex; justify-content:space-between; padding:6px 0; border:none; text-align:right;}
      td::before{content:attr(data-label); font-weight:600; color:var(--primary);}
    }
  </style></head>
  <body>
    <div class="container">
      ${getHeaderNav(session)}
      <div class="top-card">
         <div style="font-weight:600; color:var(--primary); margin-bottom:6px; font-size:15px;">当前会话主体: ${escapeHtml(session.username)}</div>
         <div style="font-size:13px; color:#555;">
           <span style="font-weight:600; color:var(--primary);">可访问查阅的白名单信箱：</span><br>
           ${session.role === 'superuser' || session.permissions.includes('mail:view:all') ? '- [最高特权: 纵览系统内所有信箱域]' : (session.accessible_emails && session.accessible_emails.length > 0 ? session.accessible_emails.map(e => `- ${escapeHtml(e)}`).join('<br>') : '- [暂未分配任何查阅权限]')}
         </div>
      </div>
      
      <div class="wrapper" style="overflow-x:auto;">
        <div style="padding:12px 16px; border-bottom:1px solid var(--border); display:flex; gap:10px; background:#faf9f7;">
          <button class="del-btn" onclick="batchDeleteMails()">🗑️ 彻底粉碎所选</button>
        </div>
        <table>
          <thead><tr><th style="width:40px;"><input type="checkbox" onchange="document.querySelectorAll('.batch-cb').forEach(cb=>cb.checked=this.checked)"></th><th>被分配的收件箱</th><th>信号源(发件人)</th><th>传输主题</th><th>落地时间</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="5" style="text-align:center;color:#666;padding:30px;">📭 当前查阅视界内没有任何邮件留存。</td></tr>'}</tbody>
        </table>
        ${generatePaginationHtml(page, totalPages, '/')}
      </div>
    </div>
    <script>
      async function batchDeleteMails() {
        const ids = Array.from(document.querySelectorAll('.batch-cb:checked')).map(cb => parseInt(cb.value));
        if (ids.length === 0) return alert('请先精准勾选需要剔除的锚点。');
        if (confirm('是否要从底层物理抹除选中的 '+ids.length+' 封邮件？一旦销毁无法回溯！')) {
          const res = await fetch('/api/batch-delete/messages', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ids}) });
          if(res.ok) location.reload(); else alert('部分或全部剔除指令失效，权限遭受拦截');
        }
      }
    </script>
  </body></html>`;
}

function generateDetailPage(message, session) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>邮件提取阅读</title>
  <style>${getCommonCss()}
    .card { background:#fff; padding:20px; border-radius:12px; box-shadow:0 1px 3px rgba(0,0,0,0.05); }
    .sub { font-size:18px; font-weight:700; margin-bottom:16px; color:var(--primary); word-break:break-all; }
    .grid { display:grid; grid-template-columns:auto 1fr; gap:8px 16px; font-size:13px; margin-bottom:20px; padding-bottom:16px; border-bottom:1px solid var(--border); }
    .lbl { color:var(--primary); font-weight:600; }
    iframe { width:100%; min-height:450px; border:1px solid var(--border); border-radius:8px; display:block; }
  </style></head>
  <body>
    <div class="container">
      ${getHeaderNav(session)}
      <a href="/" class="btn" style="display:inline-block; margin-bottom:12px; text-decoration:none; background:var(--secondary); color:var(--primary);">← 折返收件阵列</a>
      <div class="card">
        <div class="sub">${escapeHtml(message.subject || '(无主题)')}</div>
        <div class="grid">
          <div class="lbl">发送信源</div><div>${escapeHtml(message.from_address)}</div>
          <div class="lbl">接收靶点</div><div>${escapeHtml(message.mailbox_email)}</div>
          <div class="lbl">留存时间</div><div>${new Date(message.received_at).toLocaleString('zh-CN')}</div>
        </div>
        <iframe src="/raw-html/${message.id}" sandbox="allow-popups allow-popups-to-escape-sandbox"></iframe>
      </div>
    </div>
  </body></html>`;
}

function generateUserPage(users, session, page, totalPages) {
  const AVAILABLE_PERMISSIONS = [
    { key: 'mail:view:allowed', label: '查看授权箱/域邮件', desc: '查看穿透列表中指定的后缀邮件' },
    { key: 'mail:view:all', label: '查看全局所有邮件', desc: '全局查阅最高特权' },
    { key: 'mail:delete:allowed', label: '删除授权箱/域邮件', desc: '粉碎穿透列表中指定的目标' },
    { key: 'mail:delete:all', label: '删除全局所有邮件', desc: '全局粉碎特权' },
    { key: 'user:manage:restricted', label: '受限管理普通用户', desc: '仅增删改普通（USER）' },
    { key: 'user:manage:all', label: '全权管理所有账户', desc: '全局掌控所有人' },
    { key: 'log:view:all', label: '调阅全局审计日志', desc: '全量底仓行为透视' },
    { key: 'system:config:view', label: '查阅全局系统设置', desc: '只读系统配置' },
    { key: 'system:config:edit', label: '修改全局系统设置', desc: '热重载改写配置' }
  ];

  const rows = users.map(u => `
    <tr>
      <td data-label="用户名" style="font-weight:600; color:var(--primary);">${escapeHtml(u.username)}</td>
      <td data-label="角色"><span class="badge">${u.role.toUpperCase()}</span></td>
      <td data-label="状态">${u.disabled ? '<span style="color:#ef4444;font-weight:600;">❌ 已封禁</span>' : '<span style="color:#22c55e;font-weight:600;">✅ 健康</span>'}</td>
      <td data-label="管理"><button class="btn" style="padding:6px 12px; font-size:13px;" onclick="editUserById(${u.id})">分配策略与审视</button></td>
    </tr>
  `).join('');

  const checkboxHtml = AVAILABLE_PERMISSIONS.map(p => `
    <div style="background:#fff; padding:10px; border-radius:6px; border:1px solid var(--border);">
      <label style="display:flex; align-items:center; gap:8px; font-size:13px; color:var(--text); cursor:pointer;">
        <input type="checkbox" name="perms" value="${p.key}">
        <span><strong>${p.label}</strong> <code style="font-size:10px;color:var(--primary);background:var(--secondary);padding:1px 4px;border-radius:4px;">${p.key}</code></span>
      </label>
    </div>
  `).join('');

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>组织构架授权体系</title>
  <style>${getCommonCss()}
    .m-card { background:#fff; padding:24px; border-radius:12px; margin-bottom:20px; display:none; border:1px solid var(--border); box-shadow:0 4px 6px rgba(0,0,0,0.05); border-left: 6px solid var(--primary); }
    .f-grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:16px; }
    .perm-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin:12px 0; background:var(--bg); padding:16px; border-radius:8px; }
    .tpl-btn { padding:4px 8px; background:var(--secondary); border:none; border-radius:4px; font-size:12px; cursor:pointer; color:var(--primary); font-weight:600; margin-right:6px; transition:0.2s;}
    .tpl-btn:hover { background:#c7b6a4; }
    @media(max-width:768px){ .f-grid, .perm-grid { grid-template-columns:1fr; } thead { display:none; } tr { display:block; background:#fff; border-radius:8px; margin-bottom:12px; padding:12px; box-shadow:0 1px 2px rgba(0,0,0,0.05);} td { display:flex; justify-content:space-between; padding:8px 0; border:none; text-align:right;} td::before { content:attr(data-label); color:var(--primary); font-weight:600; } }
  </style></head>
  <body>
    <div class="container">
      ${getHeaderNav(session)}
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
        <h3 style="font-size:16px; font-weight:700; color:var(--primary);">👤 组织用户管控中枢</h3>
        <button class="btn" onclick="showCreateForm()">+ 孵化新系统端点</button>
      </div>

      <div class="m-card" id="formCard">
        <h4 id="fTitle" style="margin-bottom:16px; font-size:15px; font-weight:700; display:inline-block; padding-bottom:4px; color:var(--primary);">新增端点</h4>
        <form id="uForm">
          <input type="hidden" id="userId">
          <div class="f-grid">
            <div><label style="display:block;margin-bottom:6px;font-size:13px;font-weight:600;">系统账号</label><input type="text" id="uName" style="width:100%; padding:10px; border:1px solid var(--border); border-radius:6px;" required></div>
            <div><label style="display:block;margin-bottom:6px;font-size:13px;font-weight:600;">安全口令 <span id="pwdHint" style="font-weight:400;color:#666;"></span></label><input type="password" id="uPass" style="width:100%; padding:10px; border:1px solid var(--border); border-radius:6px;"></div>
          </div>
          <div class="f-grid">
            <div><label style="display:block;margin-bottom:6px;font-size:13px;font-weight:600;">下放的角色级别</label>
              <select id="uRole" style="width:100%; padding:10px; border:1px solid var(--border); border-radius:6px; background:#fff;">
                <option value="user">受限操作员 (USER)</option>
                <option value="admin">全景观察者 (ADMIN)</option>
              </select>
            </div>
          </div>
          
          <div style="margin-top:16px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <label style="font-size:14px; font-weight:700; color:var(--primary);">🛡️ 细粒度功能权限拓扑</label>
              <div><button type="button" class="tpl-btn" onclick="applyTemplate('user')">平民约束集</button><button type="button" class="tpl-btn" onclick="applyTemplate('admin')">高管特权集</button></div>
            </div>
            <div class="perm-grid">${checkboxHtml}</div>
          </div>

          <div style="margin-bottom:16px;">
            <label style="display:block;margin-bottom:6px;font-size:13px;font-weight:600; color:var(--primary);">信箱查阅穿透白名单 (允许其实际窥视的邮箱列表，一行一个)</label>
            <textarea id="uAccess" style="width:100%; height:100px; padding:10px; border:1px solid var(--border); border-radius:6px; font-family:monospace;" placeholder="alice@company.com&#10;@globaldomain.com"></textarea>
          </div>
          
          <div style="margin-bottom:20px; background:#fee2e2; padding:12px; border-radius:6px; border:1px solid #fca5a5;">
            <label style="cursor:pointer; font-weight:600; color:#b91c1c; font-size:13px;"><input type="checkbox" id="uDisabled" style="margin-right:6px; width:15px; height:15px; vertical-align:middle;"> 无条件强制熔断该账户的登录状态（拉黑）</label>
          </div>
          
          <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
            <button type="submit" class="btn">核准并保存下发指令</button>
            <button type="button" class="btn" style="background:var(--secondary); color:var(--primary);" onclick="hideForm()">隐蔽编辑面板</button>
            <button type="button" id="delBtn" class="del-btn" style="margin-left:auto; display:none;" onclick="deleteUser()">从底层彻底剥离此端点</button>
          </div>
        </form>
        
        <div id="uLogsContainer" style="margin-top:24px; padding-top:24px; border-top:2px dashed var(--secondary); display:none;"></div>
      </div>

      <div class="wrapper" style="overflow-x:auto;">
        <table>
          <thead><tr><th>通信节点名</th><th>身份标识</th><th>存活健康态</th><th>全盘操作指引</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="4" style="text-align:center;">系统中没有任何活动节点。</td></tr>'}</tbody>
        </table>
        ${generatePaginationHtml(page, totalPages, '/admin/users')}
      </div>
    </div>
    
    <script>
      const USERS_DATA = ${JSON.stringify(users)};
      let currentAction = 'create';
      
      function editUserById(id) {
        const u = USERS_DATA.find(x => x.id === id);
        if(u) editUser(u);
      }

      function applyTemplate(role) {
        const checkboxes = document.querySelectorAll('input[name="perms"]');
        checkboxes.forEach(cb => cb.checked = false);
        const tplMap = {
          user: ['mail:view:allowed', 'mail:delete:allowed'],
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
        document.getElementById('fTitle').innerText = '赋予新端点生命周期';
        document.getElementById('userId').value = '';
        document.getElementById('uName').value = ''; document.getElementById('uName').disabled = false;
        document.getElementById('uPass').required = true;
        document.getElementById('pwdHint').innerText = '(必需项)';
        document.getElementById('uRole').value = 'user';
        document.getElementById('uAccess').value = '';
        document.getElementById('uDisabled').checked = false;
        applyTemplate('user');
        document.getElementById('delBtn').style.display = 'none';
        document.getElementById('uLogsContainer').style.display = 'none';
        document.getElementById('formCard').style.display = 'block';
        document.getElementById('formCard').scrollIntoView({ behavior: 'smooth' });
      }
      
      async function editUser(u) {
        currentAction = 'update';
        document.getElementById('fTitle').innerText = '审查并修改特征指纹 - ' + u.username;
        document.getElementById('userId').value = u.id;
        document.getElementById('uName').value = u.username; document.getElementById('uName').disabled = true;
        document.getElementById('uPass').required = false;
        document.getElementById('pwdHint').innerText = '(若不更改其口令请留空)';
        document.getElementById('uRole').value = u.role;
        document.getElementById('uDisabled').checked = u.disabled === 1;
        
        const checkboxes = document.querySelectorAll('input[name="perms"]');
        checkboxes.forEach(cb => { cb.checked = (u.permissions || []).includes(cb.value); });
        document.getElementById('uAccess').value = (u.accessible_emails || []).join('\\n');
        document.getElementById('delBtn').style.display = 'inline-block';
        
        const lc = document.getElementById('uLogsContainer');
        lc.style.display = 'block';
        lc.innerHTML = '<div style="color:#666;">⏳ 系统正在底层抽拉该端点的动作轨迹...</div>';
        
        try {
           const res = await fetch('/api/users/' + u.id + '/logs');
           const data = await res.json();
           let html = '<h5 style="color:var(--primary); font-size:15px; margin-bottom:12px;">🔍 专属行为回放室 (Max: 50条记录)</h5>';
           if(data.logs.length === 0) {
             html += '<div style="color:#666;font-size:13px;">深渊中未观测到此节点的任何留痕。</div>';
           } else {
             html += '<div style="max-height:250px; overflow-y:auto; background:#f8fafc; border-radius:6px; border:1px solid var(--border); padding:10px;">';
             data.logs.forEach(l => {
               const st = l.success ? '<span style="color:#22c55e; font-weight:700;">[穿透成功]</span>' : '<span style="color:#ef4444; font-weight:700;">[遭遇拦截]</span>';
               let desc = ''; try { desc = JSON.parse(l.details).description; } catch(e) { desc = l.details; }
               html += '<div style="font-size:12px; margin-bottom:8px; border-bottom:1px solid #f1f5f9; padding-bottom:8px; color:var(--text);">';
               html += '<span style="color:#64748b;">'+new Date(l.created_at).toLocaleString()+'</span> '+st+' <strong style="color:var(--primary);">['+l.action+']</strong> ' + escapeHtml(desc);
               html += '</div>';
             });
             html += '</div>';
           }
           lc.innerHTML = html;
        } catch(e) { lc.innerHTML = '<div style="color:red;">获取异常，溯源链路遭到物理中断。</div>'; }

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
          role: document.getElementById('uRole').value,
          permissions: checkedPerms,
          accessible_emails: accessEmails,
          disabled: document.getElementById('uDisabled').checked
        };
        const res = await fetch('/admin/users', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
        if(res.ok) { window.location.reload(); } else { const d = await res.json(); alert('数据覆写坍塌: ' + d.message); }
      };
      
      async function deleteUser() {
        if(confirm('红色警告：你正在物理清退一个端点。确定此行为吗？')) {
          const res = await fetch('/admin/users', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ action: 'delete', id: document.getElementById('userId').value }) });
          if(res.ok) window.location.reload(); else alert('阻断：没有足够的超限授权执行销毁。');
        }
      }
    </script>
  </body></html>`;
}

function generateLogPage(logs, session, page, totalPages) {
  const getActionTag = (action) => {
    const map = {
      'login': { tag: '系统', color: 'var(--primary)' },
      'logout': { tag: '系统', color: 'var(--primary)' },
      'update_system_config': { tag: '系统', color: 'var(--primary)' },
      'view_message': { tag: '邮件', color: '#0369a1' },
      'delete_message': { tag: '邮件', color: '#0369a1' },
      'create_user': { tag: '管理', color: '#b45309' },
      'update_user': { tag: '管理', color: '#b45309' },
      'delete_user': { tag: '管理', color: '#b45309' },
      'update_permission': { tag: '权限', color: '#7e22ce' },
      'view_logs': { tag: '日志', color: '#047857' },
      'cleanup_logs': { tag: '日志', color: '#047857' },
      'access_denied': { tag: '安全', color: '#be123c' }
    };
    return map[action] || { tag: '未归档', color: '#666' };
  };

  const isSuper = session.role === 'superuser';

  const rows = logs.map(l => {
    let desc = '';
    try { desc = JSON.parse(l.details).description; } catch(e) { desc = l.details || ''; }
    const meta = getActionTag(l.action);
    const rs = l.success ? '<span style="color:#16a34a;font-weight:700;">成功贯通</span>' : '<span style="color:#dc2626;font-weight:700;">拒绝/失败</span>';
    
    // 【修复新增】：单项日志的可选删除按钮（只有超管可见）
    return `
      <div style="padding:16px; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; gap:12px; background:#fff; transition:0.2s;">
        <div style="display:flex; align-items:flex-start; gap:12px; flex:1;">
          <input type="checkbox" class="batch-cb" value="${l.id}" style="margin-top:4px;">
          <div style="font-size:12px; color:#666; min-width:130px; font-family:monospace; margin-top:2px;">${new Date(l.created_at).toLocaleString('zh-CN')}</div>
          <div style="font-size:14px; color:var(--text); flex:1; line-height:1.5;">
            <strong style="color:${meta.color}; margin-right:4px;">[${meta.tag}]</strong>
            <strong style="font-size:14px;">${escapeHtml(l.username)}</strong>
            <span style="color:#666; font-size:12px;">（${escapeHtml(l.ip)}）</span>
            发起 <span style="background:var(--bg); padding:2px 6px; border-radius:4px; font-weight:600; color:var(--primary);">${escapeHtml(desc)}</span> 进程 
            => 结果反馈：${rs}
          </div>
        </div>
        ${isSuper ? `<button class="del-btn" style="padding:4px 8px; font-size:12px;" onclick="deleteSingleLog(${l.id})">抹除单轨</button>` : ''}
      </div>
    `;
  }).join('');

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>底层审计阵列</title>
  <style>${getCommonCss()}</style></head>
  <body>
    <div class="container">
      ${getHeaderNav(session)}
      <div class="wrapper" style="background: #fff; overflow:hidden;">
        <div style="padding:16px 20px; border-bottom:2px solid var(--secondary); background:var(--bg); display:flex; justify-content:space-between; align-items:center;">
          <h3 style="font-size:16px; font-weight:700; margin:0; color:var(--primary);">📋 全局泛域监听池</h3>
          ${isSuper ? `<div><button class="del-btn" style="margin-right:10px;" onclick="batchDeleteLogs()">🗑️ 抹除选定面</button><button class="btn" style="background:#dc2626; padding:6px 12px; font-size:13px;" onclick="cleanupLogs()">🧹 物理粉碎过时死水</button></div>` : ''}
        </div>
        <div style="padding:10px 16px; border-bottom:1px solid var(--border); background:#faf9f7;">
           <label style="font-size:13px; font-weight:600; color:var(--primary); cursor:pointer;"><input type="checkbox" onchange="document.querySelectorAll('.batch-cb').forEach(cb=>cb.checked=this.checked)" style="vertical-align:middle;"> 标定此页全量节点</label>
        </div>
        <div style="display:flex; flex-direction:column;">
          ${rows || '<div style="padding:40px; text-align:center; color:#999;">探针当前没有任何反馈与截获信号。</div>'}
        </div>
        ${generatePaginationHtml(page, totalPages, '/admin/logs')}
      </div>
    </div>
    <script>
      async function cleanupLogs() {
        if(confirm('不可逆警告：将从阵列中拔除所有超过保留周期的陈旧日志，确认摧毁吗？')) {
          const res = await fetch('/admin/logs/cleanup', { method: 'POST' });
          if(res.ok) { const data = await res.json(); alert('系统轰炸完毕，蒸发了 ' + data.count + ' 条孤立信息。'); location.reload(); } 
          else { alert('轰炸系统启动中止！缺乏权限校验。'); }
        }
      }
      
      async function batchDeleteLogs() {
        const ids = Array.from(document.querySelectorAll('.batch-cb:checked')).map(cb => parseInt(cb.value));
        if (ids.length === 0) return alert('雷达没有探测到你的标定。');
        if(confirm('强制抽离这 '+ids.length+' 条特定轨迹面吗？')) {
          const res = await fetch('/api/batch-delete/logs', { method: 'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ids}) });
          if(res.ok) { location.reload(); } else { alert('删除遭拦截。'); }
        }
      }

      async function deleteSingleLog(id) {
        if(confirm('超管专属动作：切断抹平这一条单独的记录带吗？')) {
          const res = await fetch('/admin/logs/delete/' + id, { method: 'POST' });
          if(res.ok) { location.reload(); } else { alert('删除无权执行。'); }
        }
      }
    </script>
  </body></html>`;
}

function generateSettingsPage(config, session) {
  const isReadonly = session.role !== 'superuser' && !session.permissions.includes('system:config:edit');
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>重工管控配置台</title>
  <style>${getCommonCss()}
    .box { background:#fff; padding:30px; border-radius:12px; box-shadow:0 4px 6px rgba(0,0,0,0.05); max-width:650px; margin:0 auto; border-top: 6px solid var(--primary); }
    .g { margin-bottom:20px; }
    .g label { display:block; font-weight:600; margin-bottom:8px; color:var(--primary); font-size:14px; }
    .g input[type="number"], .g textarea { width:100%; padding:10px 12px; border:1px solid var(--border); border-radius:6px; font-size:14px; background:#fff; font-family:monospace; }
    .g input:focus, .g textarea:focus { outline:none; border-color:var(--primary); box-shadow: 0 0 0 3px rgba(73, 45, 34, 0.1); }
    .section-title { font-size:13px; font-weight:700; color:#64748b; border-bottom:1px solid var(--border); padding-bottom:6px; margin:24px 0 16px 0; text-transform:uppercase; }
  </style></head>
  <body>
    <div class="container">
      ${getHeaderNav(session)}
      <div class="box">
        <h3 style="margin-bottom:8px; font-size:18px; color:var(--primary); font-weight:800;">⚙️ 系统全局重工管控台</h3>
        <p style="color:#666; font-size:13px; margin-bottom:24px;">所递交的数字指令将跳过中转，产生即时不可阻挡的覆盖重载面。</p>
        
        <form id="sForm">
          <div class="section-title">攻防阵线策略集</div>
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">
            <div class="g">
              <label>容错试探峰值 (次)</label>
              <input type="number" id="max_login_failures" value="${config.max_login_failures}" min="1" ${isReadonly?'disabled':''}>
            </div>
            <div class="g">
              <label>熔断禁足时长 (小时)</label>
              <input type="number" id="lockout_hours" value="${config.lockout_hours}" min="1" ${isReadonly?'disabled':''}>
            </div>
          </div>
          <div class="g" style="margin-top:-10px;">
            <label>清退容错累计的衰减周期 (小时)</label>
            <input type="number" id="failure_window_hours" value="${config.failure_window_hours}" min="1" ${isReadonly?'disabled':''}>
          </div>
          <div class="g">
            <label>IP 生死黑名单 (强物理隔绝，多IP用分号 ; 切开)</label>
            <textarea id="ip_blacklist" placeholder="192.168.1.1; 10.0.0.5" style="height:60px;" ${isReadonly?'disabled':''}>${config.ip_blacklist}</textarea>
          </div>

          <div class="section-title">生命线与环境阈值控制</div>
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">
            <div class="g">
              <label>系统 JWT 签发存活期 (小时)</label>
              <input type="number" id="expiry" value="${config.session_expiry_hours}" min="1" ${isReadonly?'disabled':''}>
            </div>
            <div class="g">
              <label>底层溯源监听数据 极值期限 (天)</label>
              <input type="number" id="logRetention" value="${config.log_retention_days}" min="1" max="365" ${isReadonly?'disabled':''}>
            </div>
          </div>
          
          <div class="g" style="background:var(--bg); padding:12px; border-radius:6px; border:1px solid var(--border);">
            <label style="margin:0; cursor:pointer; font-weight:600; color:var(--primary);"><input type="checkbox" id="allow_user_change_password" style="vertical-align:middle; width:16px; height:16px; margin-right:6px;" ${config.allow_user_change_password?'checked':''} ${isReadonly?'disabled':''}> 赋予普通端点“篡改私密密钥”的权限通道</label>
          </div>
          
          ${isReadonly ? '<p style="color:#ef4444;font-size:13px; font-weight:600;">⚠️ 你当前无权进行指令下发操作。</p>' : '<button type="submit" class="btn" style="width:100%; font-size:16px; padding:12px;">拉升闸门并覆盖配置</button>'}
        </form>
      </div>
    </div>
    <script>
      if(document.getElementById('sForm')) {
        document.getElementById('sForm').onsubmit = async (e) => {
          e.preventDefault();
          const body = {
            session_expiry_hours: document.getElementById('expiry').value,
            max_login_failures: document.getElementById('max_login_failures').value,
            failure_window_hours: document.getElementById('failure_window_hours').value,
            lockout_hours: document.getElementById('lockout_hours').value,
            ip_blacklist: document.getElementById('ip_blacklist').value,
            allow_user_change_password: document.getElementById('allow_user_change_password').checked,
            log_retention_days: document.getElementById('logRetention').value
          };
          const res = await fetch('/admin/settings', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
          if(res.ok) {
            alert('新防线已经交织，全网核心重载完毕！');
            window.location.reload();
          } else {
            const data=await res.json();
            alert('系统坍塌: '+data.message);
          }
        }
      }
    </script>
  </body></html>`;
}

function getCommonCss() {
  return `
    :root { --primary: #492D22; --secondary: #D8C7B5; --bg: #F4F1ED; --text: #333333; --border: #e2e8f0; }
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; background-color:var(--bg); color:var(--text); padding:16px; }
    .container { max-width:1200px; margin:0 auto; }
    .header { display:flex; justify-content:space-between; align-items:center; background:var(--primary); color:white; padding:14px 20px; border-radius:12px; box-shadow:0 4px 6px rgba(0,0,0,0.1); margin-bottom:12px; }
    .nav-brand { font-size:16px; font-weight:700; color:var(--secondary); }
    .nav-brand a { color:var(--secondary); text-decoration:none; }
    .nav-links { display:flex; gap:14px; align-items:center; }
    .nav-item { color:var(--secondary); text-decoration:none; font-size:14px; font-weight:600; transition:opacity 0.2s;}
    .nav-item:hover { opacity:0.8; }
    .logout-btn { padding:6px 12px; background:#ef4444; color:#fff; text-decoration:none; border-radius:6px; font-size:13px; font-weight:600; transition:0.2s;}
    .logout-btn:hover { background:#dc2626; }
    .user-badge { font-size:12px; color:#666; margin-bottom:16px; padding-left:4px; font-weight:600; }
    .wrapper { background:#fff; border-radius:12px; box-shadow:0 2px 4px rgba(0,0,0,0.05); }
    table { width:100%; border-collapse:collapse; font-size:14px; text-align:left; }
    th { background:var(--secondary); padding:14px 16px; font-weight:700; color:var(--primary); border-bottom:2px solid #c7b6a4; }
    td { padding:14px 16px; border-bottom:1px solid var(--border); color:var(--text); vertical-align:middle; }
    tr:hover { background-color:#faf9f7; }
    .link { color:var(--primary); text-decoration:none; font-weight:700; }
    .link:hover { text-decoration:underline; }
    .badge { padding:4px 8px; border-radius:4px; font-size:11px; font-weight:700; background:var(--secondary); color:var(--primary); }
    .btn { padding:10px 16px; background:var(--primary); color:white; border:none; border-radius:6px; font-size:14px; font-weight:600; cursor:pointer; transition:0.2s;}
    .btn:hover { background:#3a241b; }
    .del-btn { padding:6px 12px; background:#fff; color:#ef4444; border:1px solid #fee2e2; border-radius:6px; cursor:pointer; font-size:13px; font-weight:600; transition:0.2s; }
    .del-btn:hover { background:#ef4444; color:#fff; }
    .top-card { background:#fff; padding:16px; border-radius:8px; margin-bottom:16px; box-shadow:0 1px 3px rgba(0,0,0,0.05); border-left: 4px solid var(--primary); }
  `;
}

function escapeHtml(unsafe) {
  if (!unsafe) return '';
  return String(unsafe).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}
