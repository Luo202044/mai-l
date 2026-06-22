function generateUserPage(users, session) {
  // 定义前端渲染可用的权限定义列表（用于生成可视化勾选框）
  const AVAILABLE_PERMISSIONS = [
    { key: 'mail:view:own', label: '查看专属邮箱邮件', desc: '仅允许查看与自己绑定的专属邮箱邮件' },
    { key: 'mail:view:allowed', label: '查看授权箱/域邮件', desc: '允许查看在穿透列表中指定的邮箱或域名后缀邮件' },
    { key: 'mail:view:all', label: '查看全局所有邮件', desc: '拥有全局邮件查看最高特权（超管/管理员默认）' },
    { key: 'mail:delete:own', label: '删除专属邮箱邮件', desc: '允许删除自己专属邮箱接收到的邮件' },
    { key: 'mail:delete:allowed', label: '删除授权箱/域邮件', desc: '允许删除穿透列表中指定的目标邮件' },
    { key: 'mail:delete:all', label: '删除全局所有邮件', desc: '可任意粉碎系统内的任何邮件' },
    { key: 'user:manage:restricted', label: '受限管理普通用户', desc: '管理员专属：仅允许增删改普通（USER）角色' },
    { key: 'user:manage:all', label: '全权管理所有账户', desc: '超管专属：可管理包含普通管理员在内的所有账户' },
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

  // 渲染可视化勾选框 HTML 骨架
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
    
    /* 可视化权限网格 */
    .perm-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin:12px 0 20px 0; background:#f8fafc; padding:16px; border-radius:8px; border:1px solid #e2e8f0; }
    .perm-item { background:#fff; padding:10px 12px; border-radius:6px; border:1px solid #e2e8f0; }
    .perm-label { display:flex; align-items:center; gap:8px; font-size:14px; color:#0f172a; cursor:pointer; }
    .perm-label input { width:16px; height:16px; cursor:pointer; }
    .perm-desc { font-size:12px; color:#64748b; margin-top:4px; padding-left:24px; }
    
    .tpl-btn { padding:4px 8px; background:#f1f5f9; border:1px solid #cbd5e1; border-radius:4px; font-size:12px; cursor:pointer; color:#475569; margin-right:6px; }
    .tpl-btn:hover { background:#e2e8f0; color:#0f172a; }
    
    @media(max-width:768px){ 
      .f-grid, .perm-grid { grid-template-columns:1fr; } 
      thead { display:none; }
      tr { display:block; background:#fff; border-radius:8px; margin-bottom:12px; padding:12px; box-shadow:0 1px 2px rgba(0,0,0,0.05);}
      td { display:flex; justify-content:space-between; padding:8px 0; border:none; text-align:right;}
      td::before { content:attr(data-label); color:#64748b; font-weight:500; }
    }
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
                <button type="button" class="tpl-btn" onclick="applyTemplate('user')">一键套用标准普通用户模板</button>
                <button type="button" class="tpl-btn" onclick="applyTemplate('admin')">一键套用标准管理员模板</button>
              </div>
            </div>
            <div class="perm-grid">${checkboxHtml}</div>
          </div>

          <div class="g" style="margin-bottom:16px;">
            <label style="display:block;margin-bottom:6px;font-size:13px;font-weight:500;">允许额外穿透查看的具体箱/域名白名单 (一行一个，例如输入 <code>@domain.com</code> 代表允许看该域名下所有别名别名)</label>
            <textarea id="uAccess" style="width:100%; height:80px; padding:10px; border:1px solid #cbd5e1; border-radius:6px; font-family:monospace;" placeholder="example@test.com&#10;@specdomain.com"></textarea>
          </div>
          <div class="g" style="margin-bottom:20px; background:#fff1f2; padding:10px; border-radius:6px; border:1px solid #ffe4e6;">
            <label style="cursor:pointer; font-weight:500; color:#991b1b; font-size:14px;"><input type="checkbox" id="uDisabled" style="margin-right:6px; width:15px; height:15px; vertical-align:middle;"> 临时全面封锁封禁此账户（将导致该账户被踢下线且无法登录）</label>
          </div>
          
          <div style="display:flex; gap:10px;">
            <button type="submit" class="btn">持久化保存策略</button>
            <button type="button" class="btn" style="background:#64748b;" onclick="hideForm()">放弃返回</button>
            <button type="button" id="delBtn" class="btn" style="background:#ef4444; margin-left:auto; display:none;" onclick="deleteUser()">彻底注销删除账户</button>
          </div>
        </form>
      </div>

      <div class="wrapper" style="overflow-x:auto;">
        <table>
          <thead><tr><th>用户名</th><th>业务角色</th><th>绑定的专属箱</th><th>当前账户状态</th><th>操作管理</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="5" style="text-align:center;color:#94a3b8;">暂无分配的用户。</td></tr>'}</tbody>
        </table>
      </div>
    </div>
    <script>
      let currentAction = 'create';
      
      // 一键应用权限策略模板
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
        applyTemplate('user'); // 默认勾选普通用户模板
        document.getElementById('delBtn').style.display = 'none';
        document.getElementById('formCard').style.display = 'block';
        document.getElementById('formCard').scrollIntoView({ behavior: 'smooth' });
      }

      function editUser(u) {
        currentAction = 'update';
        document.getElementById('fTitle').innerText = '修改账户授权策略 - ' + u.username;
        document.getElementById('userId').value = u.id;
        document.getElementById('uName').value = u.username; document.getElementById('uName').disabled = true;
        document.getElementById('uPass').required = false;
        document.getElementById('pwdHint').innerText = '(留空代表维持原密码)';
        document.getElementById('uEmail').value = u.email || '';
        document.getElementById('uRole').value = u.role;
        document.getElementById('uDisabled').checked = u.disabled === 1;
        
        // 渲染勾选状态
        const checkboxes = document.querySelectorAll('input[name="perms"]');
        checkboxes.forEach(cb => {
          cb.checked = u.permissions.includes(cb.value);
        });

        // 格式化文本域展现
        document.getElementById('uAccess').value = (u.accessible_emails || []).join('\\n');
        
        document.getElementById('delBtn').style.display = 'inline-block';
        document.getElementById('formCard').style.display = 'block';
        document.getElementById('formCard').scrollIntoView({ behavior: 'smooth' });
      }

      function hideForm() { document.getElementById('formCard').style.display = 'none'; }
      
      document.getElementById('uForm').onsubmit = async (e) => {
        e.preventDefault();
        
        // 获取选中的可视化权限数组
        const checkedPerms = Array.from(document.querySelectorAll('input[name="perms"]:checked')).map(cb => cb.value);
        // 处理穿透白名单文本域
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
        
        const res = await fetch('/admin/users', { 
          method:'POST', 
          headers:{'Content-Type':'application/json'}, 
          body:JSON.stringify(body) 
        });
        
        if(res.ok) { location.reload(); } 
        else { const d = await res.json(); alert('配置同步失败: ' + d.message); }
      };

      async function deleteUser() {
        if(confirm('确定要彻底物理注销删除该用户账户吗？一旦操作将无法撤回！')) {
          const body = { action: 'delete', id: document.getElementById('userId').value };
          const res = await fetch('/admin/users', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
          if(res.ok) location.reload(); else alert('注销失败，权限不足或安全原因被系统驳回');
        }
      }
    </script>
  </body></html>`;
}
