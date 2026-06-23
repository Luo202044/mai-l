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
      
      if (session.role === 'superuser') return new Response(JSON.stringify({message: '超管账户不支持在此修改密码'}), {status: 403});
      if (!session.permissions.includes('user:self:password')) return new Response(JSON.stringify({message: '您的账户没有修改密码的权限'}), {status: 403});

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
      return new Response(generateProfilePage(session), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    // --- 登录系统 ---
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
            await logAction(-1, username, 'login', 'user', null, '触发黑名单IP拦截', false);
            return new Response(JSON.stringify({ success: false, message: '当前 IP 已被管理员列入黑名单，禁止登录。' }), { status: 403 });
          }
        }

        if (env.CONFIG_KV) {
          const isLocked = await env.CONFIG_KV.get(`lockout:${clientIp}`);
          if (isLocked) {
             await logAction(-1, username, 'login', 'user', null, '触发IP频繁失败锁定拦截', false);
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
              await logAction(user.id, username, 'login', 'user', user.id, '系统登录（账户被封禁）', false);
              return new Response(JSON.stringify({ success: false, message: '账户已被禁用' }), { status: 403 });
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

    // 🛡️ JWT 全局鉴权
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
        await logAction(session.user_id, session.username, 'view_message', 'message', messageId, `查看邮件: ${message.subject}`, true);
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
        if (!message) return new Response(JSON.stringify({ success: false, message: '未找到该邮件' }), { status: 404 });

        if (!checkMailAccess(session, message.email, 'delete')) {
          await logAction(session.user_id, session.username, 'access_denied', 'message', messageId, `越权尝试删除邮件`, false);
          return new Response(JSON.stringify({ success: false, message: '权限不足' }), { status: 403 });
        }

        await env.DB.prepare('DELETE FROM messages WHERE id = ?').bind(messageId).run();
        await logAction(session.user_id, session.username, 'delete_message', 'message', messageId, `删除了邮件: ${message.subject}`, true);
        return new Response(JSON.stringify({ success: true }));
      } catch (e) { return new Response(e.message, { status: 500 }); }
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
         await logAction(session.user_id, session.username, 'delete_message', 'message', null, `执行批量删除邮件，共 ${authorizedIds.length} 条`, true);
      }
      return new Response(JSON.stringify({ success: true, count: authorizedIds.length }));
    }

    // --- 获取指定用户的操作日志 API ---
    const logMatch = path.match(/^\/api\/users\/(\d+)\/logs$/);
    if (logMatch && request.method === 'GET') {
      if (!hasPermission('user:manage:restricted') && !hasPermission('user:manage:all')) return new Response(JSON.stringify({error: 'Forbidden'}), {status: 403});
      try {
        const targetIdInt = parseInt(logMatch[1], 10);
        const logs = await env.DB.prepare(`SELECT * FROM audit_logs WHERE user_id = ? OR (target_type = 'user' AND target_id = ?) ORDER BY created_at DESC LIMIT 50`).bind(targetIdInt, String(targetIdInt)).all();
        return new Response(JSON.stringify({logs: logs.results}), {headers:{'Content-Type':'application/json'}});
      } catch(e) {
        return new Response(JSON.stringify({error: e.message}), {status: 500});
      }
    }

    // --- 用户管理 ---
    if (path === '/admin/users') {
      if (!hasPermission('user:manage:restricted') && !hasPermission('user:manage:all')) return new Response('无权访问', { status: 403 });

      if (request.method === 'GET') {
        const page = parseInt(url.searchParams.get('page')) || 1;
        const size = parseInt(url.searchParams.get('size')) || 20;
        const offset = (page - 1) * size;
        const countRes = await env.DB.prepare('SELECT COUNT(*) as total FROM users').first();
        const totalPages = Math.ceil(countRes.total / size);
        const users = await env.DB.prepare('SELECT id, username, email, role, permissions, accessible_emails, disabled, created_at FROM users ORDER BY id DESC LIMIT ? OFFSET ?').bind(size, offset).all();
        
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

          // 【安全防线 1】：绝不允许低权限管理员篡改、创建出更高阶的 Admin 角色
          if (!hasPermission('user:manage:all') && role === 'admin') {
              return new Response(JSON.stringify({ success: false, message: '越权拦截：无权创建或提权为管理员' }), { status: 403 });
          }

          // 【安全防线 2】：提权漏洞修复。任何人分配的功能权限，必须被包含在操作者自身拥有的权限中！
          if (session.role !== 'superuser') {
              const unauthorizedPerms = (permissions || []).filter(p => !session.permissions.includes(p));
              if (unauthorizedPerms.length > 0) {
                  return new Response(JSON.stringify({ success: false, message: '越权拦截：您不能赋予他人您自身都不具备的功能权限' }), { status: 403 });
              }
          }

          // 【安全防线 3】：数据越界修复。分配白名单邮箱时，必须被包含在操作者的白名单内！
          if (session.role !== 'superuser' && !hasPermission('mail:view:all')) {
              const unauthorizedEmails = (accessible_emails || []).filter(targetEmail => {
                  return !(session.accessible_emails || []).some(allowed => {
                      if (allowed.startsWith('@')) return targetEmail.endsWith(allowed);
                      return allowed === targetEmail;
                  });
              });
              if (unauthorizedEmails.length > 0) {
                  return new Response(JSON.stringify({ success: false, message: '越权拦截：您不能分配超脱于您自身管辖范围外的邮箱/域名' }), { status: 403 });
              }
          }

          if (action === 'create') {
            const pwdHash = await hashPassword(password);
            const res = await env.DB.prepare(`INSERT INTO users (username, password_hash, role, permissions, accessible_emails, created_by) VALUES (?, ?, ?, ?, ?, ?)`).bind(username, pwdHash, role, JSON.stringify(permissions), JSON.stringify(accessible_emails), session.user_id).run();
            await logAction(session.user_id, session.username, 'create_user', 'user', res.meta.last_row_id, `新增用户: ${username} [${role}]`, true);
            return new Response(JSON.stringify({ success: true }));
          }

          if (action === 'update') {
            const target = await env.DB.prepare('SELECT role, permissions, accessible_emails FROM users WHERE id = ?').bind(id).first();
            if (!target) return new Response(JSON.stringify({ success: false, message: '找不到用户' }), { status: 404 });
            
            if (target.role === 'admin' && !hasPermission('user:manage:all')) return new Response(JSON.stringify({ success: false, message: '越权拦截：受限管理员无法修改全权管理员' }), { status: 403 });

            let updateSql = `UPDATE users SET role = ?, permissions = ?, accessible_emails = ?, disabled = ?, token_version = token_version + 1`;
            let params = [role, JSON.stringify(permissions), JSON.stringify(accessible_emails), disabled ? 1 : 0];
            if (password && password.trim() !== '') {
              const newHash = await hashPassword(password);
              updateSql += `, password_hash = ?`; params.push(newHash);
            }
            updateSql += ` WHERE id = ?`; params.push(id);
            await env.DB.prepare(updateSql).bind(...params).run();
            
            await logAction(session.user_id, session.username, 'update_user', 'user', id, `编辑用户信息: ${username}`, true);
            if (target.permissions !== JSON.stringify(permissions) || target.accessible_emails !== JSON.stringify(accessible_emails)) {
              await logAction(session.user_id, session.username, 'update_permission', 'user', id, `修改了用户权限或可访问邮箱: ${username}`, true);
            }
            return new Response(JSON.stringify({ success: true }));
          }

          if (action === 'delete') {
            const target = await env.DB.prepare('SELECT role FROM users WHERE id = ?').bind(id).first();
            if (target && target.role === 'admin' && !hasPermission('user:manage:all')) {
                return new Response(JSON.stringify({ success: false, message: '越权拦截：无法删除管理员账户' }), { status: 403 });
            }
            await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
            await logAction(session.user_id, session.username, 'delete_user', 'user', id, `删除了用户 ID: ${id}`, true);
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

    if (path === '/admin/logs/cleanup' && request.method === 'POST') {
      if (session.role !== 'superuser') return new Response(JSON.stringify({ success: false, message: '仅超级管理员可执行日志清理' }), { status: 403 });
      try {
        const config = await getSystemConfig(env);
        const days = config.log_retention_days || 30;
        const result = await env.DB.prepare("DELETE FROM audit_logs WHERE created_at < datetime('now', ?)").bind(`-${days} days`).run();
        await logAction(session.user_id, session.username, 'cleanup_logs', 'log', null, `清理了保留天数(${days}天)外的过期日志，共 ${result.meta.changes} 条`, true);
        return new Response(JSON.stringify({ success: true, count: result.meta.changes }), { headers: { 'Content-Type': 'application/json' } });
      } catch (e) { return new Response(JSON.stringify({ success: false, message: e.message }), { status: 500 }); }
    }

    if (path.startsWith('/admin/logs/delete/') && request.method === 'POST') {
      if (session.role !== 'superuser') return new Response(JSON.stringify({ success: false, message: '权限拒绝' }), { status: 403 });
      const logId = path.split('/')[4];
      try {
        await env.DB.prepare("DELETE FROM audit_logs WHERE id = ?").bind(logId).run();
        return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
      } catch (e) { return new Response(JSON.stringify({ success: false, message: e.message }), { status: 500 }); }
    }

    if (path === '/api/batch-delete/logs' && request.method === 'POST') {
      if (session.role !== 'superuser') return new Response('Forbidden', {status:403});
      const { ids } = await request.json();
      if (!Array.isArray(ids) || ids.length === 0) return new Response('Bad Request', { status: 400 });
      const placeholders = ids.map(() => '?').join(',');
      await env.DB.prepare(`DELETE FROM audit_logs WHERE id IN (${placeholders})`).bind(...ids).run();
      await logAction(session.user_id, session.username, 'delete_message', 'log', null, `批量删除了系统日志，共 ${ids.length} 条`, true);
      return new Response(JSON.stringify({ success: true }));
    }

    // --- 系统设置 ---
    if (path === '/admin/settings' && hasPermission('system:config:view')) {
      if (request.method === 'GET') {
        const config = await getSystemConfig(env);
        return new Response(generateSettingsPage(config, session), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }
      
      if (request.method === 'POST' && hasPermission('system:config:edit')) {
        try {
          const body = await request.json();
          if (env.CONFIG_KV) {
            const newConfig = {
              log_retention_days: parseInt(body.log_retention_days, 10) || 30,
              session_expiry_hours: parseInt(body.session_expiry_hours, 10) || 24,
              max_login_failures: parseInt(body.max_login_failures, 10) || 5,
              failure_window_hours: parseInt(body.failure_window_hours, 10) || 1,
              lockout_hours: parseInt(body.lockout_hours, 10) || 2,
              ip_blacklist: body.ip_blacklist || ""
            };
            await env.CONFIG_KV.put('system_config', JSON.stringify(newConfig));
          }
          await logAction(session.user_id, session.username, 'update_system_config', 'system_config', null, '修改了系统全局配置', true);
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

async function getSystemConfig(env) {
  const defaultConfig = { log_retention_days: 30, session_expiry_hours: 24, max_login_failures: 5, failure_window_hours: 1, lockout_hours: 2, ip_blacklist: "" };
  if (!env.CONFIG_KV) return defaultConfig;
  const val = await env.CONFIG_KV.get('system_config', 'json');
  return val ? { ...defaultConfig, ...val } : defaultConfig;
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
// 4. 🎨 凡戴克棕 + 浅卡其色 UI 系统
// ==========================================
function getHeaderNav(session) {
  const hasUserManage = session.role === 'superuser' || session.permissions.includes('user:manage:restricted') || session.permissions.includes('user:manage:all');
  const hasLogs = session.role === 'superuser' || session.permissions.includes('log:view:all');
  const hasSettings = session.role === 'superuser' || session.permissions.includes('system:config:view');

  return `
    <div class="header">
      <div class="nav-brand"><a href="/">📬 邮件接收系统</a></div>
      <div class="nav-links">
        <a href="/" class="nav-item">收件箱</a>
        ${hasUserManage ? `<a href="/admin/users" class="nav-item">用户管理</a>` : ''}
        ${hasLogs ? `<a href="/admin/logs" class="nav-item">审计日志</a>` : ''}
        ${hasSettings ? `<a href="/admin/settings" class="nav-item">系统配置</a>` : ''}
        <a href="/profile" class="nav-item">账号安全</a>
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

function generateProfilePage(session) {
  const isSuper = session.role === 'superuser';
  const canChange = session.permissions.includes('user:self:password') && !isSuper;

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
        <h3 style="margin-bottom:16px; color:var(--primary);">🔒 修改密码</h3>
        ${isSuper ? '<p style="color:#ef4444; background:#fee2e2; padding:10px; border-radius:6px;">超管账户不支持在此页面修改密码。</p>' : ''}
        ${!isSuper && !canChange ? '<p style="color:#ef4444; background:#fee2e2; padding:10px; border-radius:6px;">您的账户没有修改密码的权限，请联系管理员分配权限。</p>' : ''}
        
        ${canChange ? `
        <form id="pwdForm">
          <div class="g"><label>当前密码</label><input type="password" id="oldPwd" required></div>
          <div class="g"><label>新密码</label><input type="password" id="newPwd" required></div>
          <div class="g"><label>确认新密码</label><input type="password" id="newPwd2" required></div>
          <button type="submit" class="btn" style="width:100%;">保存修改</button>
        </form>
        <script>
          document.getElementById('pwdForm').onsubmit = async (e) => {
             e.preventDefault();
             const o = document.getElementById('oldPwd').value;
             const n1 = document.getElementById('newPwd').value;
             const n2 = document.getElementById('newPwd2').value;
             if(n1 !== n2) return alert('两次新密码输入不一致');
             const res = await fetch('/api/change-password', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({oldPwd:o, newPwd:n1}) });
             if(res.ok) { alert('密码修改成功，请使用新密码重新登录。'); window.location.href='/logout'; }
             else { const d = await res.json(); alert(d.message); }
          }
        </script>
        ` : ''}
      </div>
    </div>
  </body></html>`;
}

function generateLoginPage() {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>用户登录</title>
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
      <div class="h"><h2>📧 系统登录</h2></div>
      <div class="err" id="e"></div>
      <form id="f">
        <div class="g"><label>用户名</label><input type="text" id="u" required autofocus></div>
        <div class="g"><label>密码</label><input type="password" id="p" required></div>
        <button type="submit" class="btn">登录</button>
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
      <td data-label="操作">
        <div class="action-group">
          <a href="/view/${msg.id}" class="btn" style="padding:6px 12px; font-size:13px; text-decoration:none; display:inline-block; text-align:center;">查看</a>
          <button class="del-btn" style="padding:6px 12px; font-size:13px;" onclick="delMail(${msg.id})">删除</button>
        </div>
      </td>
    </tr>
  `).join('');

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>收件箱</title>
  <style>${getCommonCss()}
    .action-group { display:flex; gap:8px; align-items:center; }
    @media(max-width:768px){
      thead{display:none;} tr{display:block; background:#fff; border-radius:8px; margin-bottom:12px; padding:12px; box-shadow:0 1px 2px rgba(0,0,0,0.05);}
      td{display:flex; justify-content:space-between; padding:6px 0; border:none; text-align:right;}
      td::before{content:attr(data-label); font-weight:600; color:var(--primary);}
      .action-group { width: 100%; justify-content: space-between; margin-top:8px; }
      .action-group > * { flex: 1; }
    }
  </style></head>
  <body>
    <div class="container">
      ${getHeaderNav(session)}
      <div class="top-card">
         <div style="font-weight:600; color:var(--primary); margin-bottom:6px; font-size:15px;">当前登录用户: ${escapeHtml(session.username)}</div>
         <div style="font-size:13px; color:#555;">
           <span style="font-weight:600; color:var(--primary);">可访问的邮箱白名单：</span><br>
           ${session.role === 'superuser' || session.permissions.includes('mail:view:all') ? '- [拥有全局访问权限]' : (session.accessible_emails && session.accessible_emails.length > 0 ? session.accessible_emails.map(e => `- ${escapeHtml(e)}`).join('<br>') : '- [暂无分配的邮箱]')}
         </div>
      </div>
      
      <div class="wrapper" style="overflow-x:auto;">
        <div style="padding:12px 16px; border-bottom:1px solid var(--border); display:flex; gap:10px; background:#faf9f7;">
          <button class="del-btn" onclick="batchDeleteMails()">🗑️ 批量删除</button>
        </div>
        <table>
          <thead><tr><th style="width:40px;"><input type="checkbox" onchange="document.querySelectorAll('.batch-cb').forEach(cb=>cb.checked=this.checked)"></th><th>收件邮箱</th><th>发件人</th><th>主题</th><th>接收时间</th><th style="width:140px;">操作</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="6" style="text-align:center;color:#666;padding:30px;">暂无邮件记录。</td></tr>'}</tbody>
        </table>
        ${generatePaginationHtml(page, totalPages, '/')}
      </div>
    </div>
    <script>
      async function batchDeleteMails() {
        const ids = Array.from(document.querySelectorAll('.batch-cb:checked')).map(cb => parseInt(cb.value));
        if (ids.length === 0) return alert('请先勾选需要删除的邮件');
        if (confirm('确定要永久删除选中的 '+ids.length+' 封邮件吗？')) {
          const res = await fetch('/api/batch-delete/messages', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ids}) });
          if(res.ok) location.reload(); else alert('删除失败，权限不足。');
        }
      }
      async function delMail(id) {
        if(confirm('确定要彻底删除此邮件记录吗？')) {
          const res = await fetch('/delete/' + id, { method:'POST' });
          if(res.ok) location.reload(); else alert('删除失败，权限不足。');
        }
      }
    </script>
  </body></html>`;
}

function generateDetailPage(message, session) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>邮件详情</title>
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
      <a href="/" class="btn" style="display:inline-block; margin-bottom:12px; text-decoration:none; background:var(--secondary); color:var(--primary);">← 返回收件箱</a>
      <div class="card">
        <div class="sub">${escapeHtml(message.subject || '(无主题)')}</div>
        <div class="grid">
          <div class="lbl">发件人</div><div>${escapeHtml(message.from_address)}</div>
          <div class="lbl">收件人</div><div>${escapeHtml(message.mailbox_email)}</div>
          <div class="lbl">接收时间</div><div>${new Date(message.received_at).toLocaleString('zh-CN')}</div>
        </div>
        <iframe src="/raw-html/${message.id}" sandbox="allow-popups allow-popups-to-escape-sandbox"></iframe>
      </div>
    </div>
  </body></html>`;
}

function generateUserPage(users, session, page, totalPages) {
  const AVAILABLE_PERMISSIONS = [
    { key: 'mail:view:allowed', label: '查看授权箱/域邮件', desc: '允许查看白名单中指定的后缀邮件' },
    { key: 'mail:view:all', label: '查看所有邮件', desc: '允许查看系统内所有邮件' },
    { key: 'mail:delete:allowed', label: '删除授权箱/域邮件', desc: '允许删除白名单中指定的后缀邮件' },
    { key: 'mail:delete:all', label: '删除所有邮件', desc: '允许删除系统内所有邮件' },
    { key: 'user:manage:restricted', label: '受限管理普通用户', desc: '允许新增/编辑/删除普通用户' },
    { key: 'user:manage:all', label: '管理所有账户', desc: '允许管理包含管理员在内的所有账户' },
    { key: 'user:self:password', label: '修改自身密码', desc: '允许当前用户在面板中修改自己的密码' },
    { key: 'log:view:all', label: '查看审计日志', desc: '允许查看所有用户的操作日志' },
    { key: 'system:config:view', label: '查看系统配置', desc: '允许只读访问系统设置面板' },
    { key: 'system:config:edit', label: '修改系统配置', desc: '允许修改并保存系统全局设置' }
  ];

  const rows = users.map(u => `
    <tr>
      <td data-label="用户名" style="font-weight:600; color:var(--primary);">${escapeHtml(u.username)}</td>
      <td data-label="角色"><span class="badge">${u.role === 'admin' ? '管理员' : '普通用户'}</span></td>
      <td data-label="状态">${u.disabled ? '<span style="color:#ef4444;font-weight:600;">禁用</span>' : '<span style="color:#22c55e;font-weight:600;">正常</span>'}</td>
      <td data-label="操作"><button class="btn" style="padding:6px 12px; font-size:13px;" onclick="editUserById(${u.id})">编辑用户</button></td>
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

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>用户管理</title>
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
        <h3 style="font-size:16px; font-weight:700; color:var(--primary);">👤 用户管理</h3>
        <button class="btn" onclick="showCreateForm()">+ 新增用户</button>
      </div>

      <div class="m-card" id="formCard">
        <h4 id="fTitle" style="margin-bottom:16px; font-size:15px; font-weight:700; display:inline-block; padding-bottom:4px; color:var(--primary);">新增用户</h4>
        <form id="uForm">
          <input type="hidden" id="userId">
          <div class="f-grid">
            <div><label style="display:block;margin-bottom:6px;font-size:13px;font-weight:600;">用户名</label><input type="text" id="uName" style="width:100%; padding:10px; border:1px solid var(--border); border-radius:6px;" required></div>
            <div><label style="display:block;margin-bottom:6px;font-size:13px;font-weight:600;">密码 <span id="pwdHint" style="font-weight:400;color:#666;"></span></label><input type="password" id="uPass" style="width:100%; padding:10px; border:1px solid var(--border); border-radius:6px;"></div>
          </div>
          <div class="f-grid">
            <div><label style="display:block;margin-bottom:6px;font-size:13px;font-weight:600;">角色</label>
              <select id="uRole" style="width:100%; padding:10px; border:1px solid var(--border); border-radius:6px; background:#fff;">
                <option value="user">普通用户 (USER)</option>
                <option value="admin">管理员 (ADMIN)</option>
              </select>
            </div>
          </div>
          
          <div style="margin-top:16px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <label style="font-size:14px; font-weight:700; color:var(--primary);">🛡️ 权限分配</label>
              <div><button type="button" class="tpl-btn" onclick="applyTemplate('user')">普通用户模板</button><button type="button" class="tpl-btn" onclick="applyTemplate('admin')">管理员模板</button></div>
            </div>
            <div class="perm-grid">${checkboxHtml}</div>
          </div>

          <div style="margin-bottom:16px;">
            <label style="display:block;margin-bottom:6px;font-size:13px;font-weight:600; color:var(--primary);">可访问邮箱白名单 (一行一个，例如填写 @example.com)</label>
            <textarea id="uAccess" style="width:100%; height:100px; padding:10px; border:1px solid var(--border); border-radius:6px; font-family:monospace;" placeholder="alice@company.com&#10;@globaldomain.com"></textarea>
          </div>
          
          <div style="margin-bottom:20px; background:#fee2e2; padding:12px; border-radius:6px; border:1px solid #fca5a5;">
            <label style="cursor:pointer; font-weight:600; color:#b91c1c; font-size:13px;"><input type="checkbox" id="uDisabled" style="margin-right:6px; width:15px; height:15px; vertical-align:middle;"> 禁用此账户（禁止登录）</label>
          </div>
          
          <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
            <button type="submit" class="btn">保存设置</button>
            <button type="button" class="btn" style="background:var(--secondary); color:var(--primary);" onclick="hideForm()">取消返回</button>
            <button type="button" id="delBtn" class="del-btn" style="margin-left:auto; display:none;" onclick="deleteUser()">删除账户</button>
          </div>
        </form>
        
        <div id="uLogsContainer" style="margin-top:24px; padding-top:24px; border-top:2px dashed var(--secondary); display:none;"></div>
      </div>

      <div class="wrapper" id="userListCard" style="overflow-x:auto;">
        <table>
          <thead><tr><th>用户名</th><th>角色</th><th>状态</th><th>操作</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="4" style="text-align:center;">暂无用户。</td></tr>'}</tbody>
        </table>
        ${generatePaginationHtml(page, totalPages, '/admin/users')}
      </div>
    </div>
    
    <script>
      function escapeHtml(unsafe) {
        if (!unsafe) return '';
        return String(unsafe).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
      }

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
          user: ['mail:view:allowed', 'mail:delete:allowed', 'user:self:password'],
          admin: ['mail:view:all', 'mail:delete:all', 'user:manage:restricted', 'log:view:all', 'system:config:view', 'user:self:password']
        };
        if (tplMap[role]) {
          tplMap[role].forEach(perm => {
            const el = document.querySelector('input[name="perms"][value="'+perm+'"]');
            if(el) el.checked = true;
          });
        }
      }
      
      function showCreateForm() {
        document.getElementById('userListCard').style.display = 'none'; // 隐藏底部列表
        currentAction = 'create';
        document.getElementById('fTitle').innerText = '新增用户';
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
        document.getElementById('userListCard').style.display = 'none'; // 隐藏底部列表
        currentAction = 'update';
        document.getElementById('fTitle').innerText = '编辑用户 - ' + u.username;
        document.getElementById('userId').value = u.id;
        document.getElementById('uName').value = u.username; document.getElementById('uName').disabled = true;
        document.getElementById('uPass').required = false;
        document.getElementById('pwdHint').innerText = '(不修改密码请留空)';
        document.getElementById('uRole').value = u.role;
        document.getElementById('uDisabled').checked = u.disabled === 1;
        
        const checkboxes = document.querySelectorAll('input[name="perms"]');
        checkboxes.forEach(cb => { cb.checked = (u.permissions || []).includes(cb.value); });
        document.getElementById('uAccess').value = (u.accessible_emails || []).join('\\n');
        document.getElementById('delBtn').style.display = 'inline-block';
        
        const lc = document.getElementById('uLogsContainer');
        lc.style.display = 'block';
        lc.innerHTML = '<div style="color:#666; font-size:14px;">⏳ 正在加载操作日志...</div>';
        
        try {
           const res = await fetch('/api/users/' + u.id + '/logs');
           if(!res.ok) throw new Error();
           const data = await res.json();
           let html = '<h5 style="color:var(--primary); font-size:15px; margin-bottom:12px;">🔍 账户近期操作日志 (涵盖自己发起的操作以及对该账户的变更记录)</h5>';
           if(data.logs && data.logs.length === 0) {
             html += '<div style="color:#666;font-size:13px;">暂无该用户的操作记录。</div>';
           } else if (data.logs) {
             html += '<div style="max-height:280px; overflow-y:auto; background:#f8fafc; border-radius:6px; border:1px solid var(--border); padding:10px;">';
             data.logs.forEach(l => {
               const st = l.success ? '<span style="color:#22c55e; font-weight:700;">[成功]</span>' : '<span style="color:#ef4444; font-weight:700;">[失败]</span>';
               let desc = ''; try { desc = JSON.parse(l.details).description; } catch(e) { desc = l.details; }
               html += '<div style="font-size:13px; margin-bottom:10px; border-bottom:1px solid #f1f5f9; padding-bottom:10px; color:var(--text); line-height:1.4;">';
               html += '<div style="color:#64748b; font-size:12px; margin-bottom:4px;">'+new Date(l.created_at).toLocaleString()+' | 操作者: <strong style="color:var(--primary);">'+escapeHtml(l.username)+'</strong></div>';
               html += '<div>' + st + ' <span style="background:var(--secondary); color:var(--primary); padding:1px 6px; border-radius:4px; font-weight:600; font-size:12px; margin-right:4px;">'+escapeHtml(l.action)+'</span> ' + escapeHtml(desc) + '</div>';
               html += '</div>';
             });
             html += '</div>';
           }
           lc.innerHTML = html;
        } catch(e) { lc.innerHTML = '<div style="color:#ef4444;font-size:14px;">获取操作日志异常，接口未响应或已断开。</div>'; }

        document.getElementById('formCard').style.display = 'block';
        document.getElementById('formCard').scrollIntoView({ behavior: 'smooth' });
      }
      
      function hideForm() { 
        document.getElementById('formCard').style.display = 'none'; 
        document.getElementById('userListCard').style.display = 'block'; // 取消时恢复显示列表
      }
      
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
        if(res.ok) { window.location.reload(); } else { const d = await res.json(); alert('保存失败: ' + d.message); }
      };
      
      async function deleteUser() {
        if(confirm('确定要永久删除该账户吗？此操作不可逆转。')) {
          const res = await fetch('/admin/users', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ action: 'delete', id: document.getElementById('userId').value }) });
          if(res.ok) window.location.reload(); else alert('删除失败，权限不足。');
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
    return map[action] || { tag: '操作', color: '#666' };
  };

  const isSuper = session.role === 'superuser';

  const rows = logs.map(l => {
    let desc = '';
    try { desc = JSON.parse(l.details).description; } catch(e) { desc = l.details || ''; }
    const meta = getActionTag(l.action);
    const rs = l.success ? '<span style="color:#16a34a;font-weight:700;">成功</span>' : '<span style="color:#dc2626;font-weight:700;">失败</span>';
    
    return `
      <div style="padding:16px; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; gap:12px; background:#fff; transition:0.2s;">
        <div style="display:flex; align-items:flex-start; gap:12px; flex:1;">
          <input type="checkbox" class="batch-cb" value="${l.id}" style="margin-top:4px;">
          <div style="font-size:12px; color:#666; min-width:130px; font-family:monospace; margin-top:2px;">${new Date(l.created_at).toLocaleString('zh-CN')}</div>
          <div style="font-size:14px; color:var(--text); flex:1; line-height:1.5;">
            <strong style="color:${meta.color}; margin-right:4px;">[${meta.tag}]</strong>
            <strong style="font-size:14px;">${escapeHtml(l.username)}</strong>
            <span style="color:#666; font-size:12px;">（${escapeHtml(l.ip)}）</span>
            执行 <span style="background:var(--bg); padding:2px 6px; border-radius:4px; font-weight:600; color:var(--primary);">${escapeHtml(desc)}</span> 操作 
            - 结果：${rs}
          </div>
        </div>
        ${isSuper ? `<button class="del-btn" style="padding:4px 8px; font-size:12px;" onclick="deleteSingleLog(${l.id})">删除</button>` : ''}
      </div>
    `;
  }).join('');

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>系统操作日志</title>
  <style>${getCommonCss()}</style></head>
  <body>
    <div class="container">
      ${getHeaderNav(session)}
      <div class="wrapper" style="background: #fff; overflow:hidden;">
        <div style="padding:16px 20px; border-bottom:2px solid var(--secondary); background:var(--bg); display:flex; justify-content:space-between; align-items:center;">
          <h3 style="font-size:16px; font-weight:700; margin:0; color:var(--primary);">📋 系统操作日志</h3>
          ${isSuper ? `<div><button class="del-btn" style="margin-right:10px;" onclick="batchDeleteLogs()">批量删除</button><button class="btn" style="background:#dc2626; padding:6px 12px; font-size:13px;" onclick="cleanupLogs()">清理过期日志</button></div>` : ''}
        </div>
        <div style="padding:10px 16px; border-bottom:1px solid var(--border); background:#faf9f7;">
           <label style="font-size:13px; font-weight:600; color:var(--primary); cursor:pointer;"><input type="checkbox" onchange="document.querySelectorAll('.batch-cb').forEach(cb=>cb.checked=this.checked)" style="vertical-align:middle;"> 全选本页</label>
        </div>
        <div style="display:flex; flex-direction:column;">
          ${rows || '<div style="padding:40px; text-align:center; color:#999;">暂无日志记录。</div>'}
        </div>
        ${generatePaginationHtml(page, totalPages, '/admin/logs')}
      </div>
    </div>
    <script>
      function escapeHtml(unsafe) {
        if (!unsafe) return '';
        return String(unsafe).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
      }
      
      async function cleanupLogs() {
        if(confirm('确定要清理过期的日志吗？该操作不可恢复！')) {
          const res = await fetch('/admin/logs/cleanup', { method: 'POST' });
          if(res.ok) { const data = await res.json(); alert('清理成功，删除了 ' + data.count + ' 条过期记录。'); location.reload(); } 
          else { alert('清理失败！无操作权限。'); }
        }
      }
      
      async function batchDeleteLogs() {
        const ids = Array.from(document.querySelectorAll('.batch-cb:checked')).map(cb => parseInt(cb.value));
        if (ids.length === 0) return alert('请先勾选需要删除的日志。');
        if(confirm('确定要删除选中的 '+ids.length+' 条日志吗？')) {
          const res = await fetch('/api/batch-delete/logs', { method: 'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ids}) });
          if(res.ok) { location.reload(); } else { alert('删除失败。'); }
        }
      }

      async function deleteSingleLog(id) {
        if(confirm('确定要删除此条日志吗？')) {
          const res = await fetch('/admin/logs/delete/' + id, { method: 'POST' });
          if(res.ok) { location.reload(); } else { alert('删除失败，仅限超管操作。'); }
        }
      }
    </script>
  </body></html>`;
}

function generateSettingsPage(config, session) {
  const isReadonly = session.role !== 'superuser' && !session.permissions.includes('system:config:edit');
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>系统全局设置</title>
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
        <h3 style="margin-bottom:8px; font-size:18px; color:var(--primary); font-weight:800;">⚙️ 系统配置</h3>
        <p style="color:#666; font-size:13px; margin-bottom:24px;">修改的配置将实时生效。</p>
        
        <form id="sForm">
          <div class="section-title">登录安全限制</div>
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">
            <div class="g">
              <label>最大登录失败次数 (次)</label>
              <input type="number" id="max_login_failures" value="${config.max_login_failures}" min="1" ${isReadonly?'disabled':''}>
            </div>
            <div class="g">
              <label>限制登录时长 (小时)</label>
              <input type="number" id="lockout_hours" value="${config.lockout_hours}" min="1" ${isReadonly?'disabled':''}>
            </div>
          </div>
          <div class="g" style="margin-top:-10px;">
            <label>失败次数统计周期 (小时)</label>
            <input type="number" id="failure_window_hours" value="${config.failure_window_hours}" min="1" ${isReadonly?'disabled':''}>
          </div>
          <div class="g">
            <label>IP 黑名单 (用分号分隔)</label>
            <textarea id="ip_blacklist" placeholder="192.168.1.1; 10.0.0.5" style="height:60px;" ${isReadonly?'disabled':''}>${config.ip_blacklist || ''}</textarea>
          </div>

          <div class="section-title">会话与日志设置</div>
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">
            <div class="g">
              <label>登录会话有效期 (小时)</label>
              <input type="number" id="expiry" value="${config.session_expiry_hours}" min="1" ${isReadonly?'disabled':''}>
            </div>
            <div class="g">
              <label>审计日志保留天数 (天)</label>
              <input type="number" id="logRetention" value="${config.log_retention_days}" min="1" max="365" ${isReadonly?'disabled':''}>
            </div>
          </div>
          
          ${isReadonly ? '<p style="color:#ef4444;font-size:13px; font-weight:600;">⚠️ 您的账户只有系统配置的只读权限。</p>' : '<button type="submit" class="btn" style="width:100%; font-size:16px; padding:12px;">保存系统配置</button>'}
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
            log_retention_days: document.getElementById('logRetention').value
          };
          const res = await fetch('/admin/settings', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
          if(res.ok) {
            alert('保存成功！新配置已生效。');
            window.location.reload();
          } else {
            const data=await res.json();
            alert('保存失败: '+data.message);
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
    .nav-links { display:flex; gap:14px; align-items:center; flex-wrap:wrap; }
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
