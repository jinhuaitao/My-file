/**
 * Cloudflare Worker File Manager (R2 Private Drive)
 * Version: 3.2.0
 *
 * 单文件全栈应用：Vue 3 SPA + REST API + 分享页
 * 唯一外部依赖：env.MY_BUCKET (R2)
 *
 * v3.2.0 变更
 *  - 会话改为服务端随机 token（HttpOnly Cookie），支持登出吊销与过期
 *  - 口令加盐哈希（SHA-256 + 随机盐），兼容无盐旧数据
 *  - 登录失败限流（按 IP）
 *  - 文件夹移动 / 重命名改为递归处理，并同步更新分享与上传记录
 *  - 文件列表与回收站支持分页游标，突破 500 条上限
 *  - 分享页与错误页统一做 HTML 转义，修复文件名注入
 *  - /file/ 对 HTML / SVG 等可执行类型强制下载
 *  - 统一 no-store 缓存头
 */

const CONFIG_KEY = '.sys_config.json';
const SHARES_KEY = '.sys_shares.json';
const UPLOADS_KEY = '.sys_uploads.json';
const SESSIONS_KEY = '.sys_sessions.json';
const TRASH_PREFIX = '.sys_trash/';
const SESSION_COOKIE = 'auth_session';

const SESSION_TTL = 7 * 24 * 60 * 60 * 1000;
const LOGIN_MAX_FAILS = 5;
const LOGIN_LOCK_MS = 10 * 60 * 1000;
const LIST_LIMIT = 5000;
const MAX_TEXT_SIZE = 2 * 1024 * 1024;
const HISTORY_LIMIT = 200;

const SECURE_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
};

export default {
    async fetch(request, env, ctx) {
        const res = await handleRequest(request, env, ctx);
        const headers = new Headers(res.headers);
        if (!headers.has('Cache-Control')) headers.set('Cache-Control', 'no-store');
        return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
    }
};

async function handleRequest(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const range = request.headers.get('Range');

    const getJson = (key) => readJson(env, key);
    const saveJson = (key, data) => writeJson(env, key, data);
    const json = (data, status) => new Response(JSON.stringify(data), {
        status: status || 200,
        headers: { 'Content-Type': 'application/json;charset=UTF-8', 'Cache-Control': 'no-store' }
    });
    const html = (body, status) => new Response(body, {
        status: status || 200,
        headers: { 'Content-Type': 'text/html;charset=UTF-8', 'Cache-Control': 'no-store' }
    });

    // ---------- 1. 公开：分享链接 ----------
    if (path.startsWith('/s/')) {
        const token = path.slice(3);
        const shares = (await getJson(SHARES_KEY)) || {};
        const share = shares[token];

        if (!share) return html(getErrorPageHtml('链接无效', '该分享链接不存在或已被删除。'), 404);
        if (share.expireTime && Date.now() > share.expireTime) return html(getErrorPageHtml('链接已过期', '该分享链接已超过有效期。'), 410);
        if (share.maxViews && (share.views || 0) >= share.maxViews) return html(getErrorPageHtml('访问次数耗尽', '该分享链接已达到最大访问次数限制。'), 410);

        const fileName = share.path;
        const inputPassword = url.searchParams.get('pwd');
        const mode = url.searchParams.get('mode');

        if (share.password && share.password !== inputPassword) {
            return html(getPasswordPageHtml(token, Boolean(inputPassword)), share.password && inputPassword ? 401 : 200);
        }

        const getOpts = {};
        const ifMatchHeader = request.headers.get('if-match');
        if (range) getOpts.range = range;
        if (ifMatchHeader) getOpts.onlyIf = { etag: ifMatchHeader };

        const object = await env.MY_BUCKET.get(fileName, getOpts);
        if (!object) return html(getErrorPageHtml('文件丢失', '源文件可能已被删除。'), 404);

        // 仅统计「分享页访问」，下载与内联请求不再重复计数
        if (!mode && !range) {
            share.views = (share.views || 0) + 1;
            ctx.waitUntil(saveJson(SHARES_KEY, shares));
        }

        const headers = new Headers(SECURE_HEADERS);
        object.writeHttpMetadata(headers);
        headers.set('etag', object.httpEtag);
        const shortName = fileName.split('/').pop();

        if (range && object.range) {
            headers.set('content-range', 'bytes ' + object.range.offset + '-' + object.range.end + '/' + object.size);
            headers.set('content-length', String(object.range.end - object.range.offset + 1));
            return new Response(object.body, { headers, status: 206 });
        }

        if (mode === 'download') {
            headers.set('Content-Disposition', contentDisposition(shortName, true));
            return new Response(object.body, { headers });
        }

        if (mode === 'inline') {
            const ct = (headers.get('content-type') || '').toLowerCase();
            const unsafe = isExecutableType(ct) || isExecutableExtension(shortName);
            headers.set('Content-Disposition', contentDisposition(shortName, unsafe));
            return new Response(object.body, { headers });
        }

        return html(getSharePageHtml(shortName, object.size, token, object.httpMetadata && object.httpMetadata.contentType, share.password));
    }

    // ---------- 2. 鉴权与初始化 ----------
    const config = await getJson(CONFIG_KEY);
    const isInitialized = config !== null;

    if (path === '/api/setup' && method === 'POST') {
        if (isInitialized) return json({ success: false, msg: '系统已初始化' }, 403);
        let data;
        try { data = await request.json(); } catch (e) { return json({ success: false, msg: '请求格式错误' }, 400); }
        const username = String(data.username || '').trim();
        const password = String(data.password || '');
        if (!username || username.length > 32) return json({ success: false, msg: '用户名不能为空且不超过 32 字符' }, 400);
        if (password.length < 6) return json({ success: false, msg: '密码至少 6 位' }, 400);

        const salt = randomHex(16);
        await saveJson(CONFIG_KEY, { username, salt, password: await hashText(salt + password), createdAt: Date.now() });
        await saveJson(SHARES_KEY, {});
        await saveJson(UPLOADS_KEY, []);
        await saveJson(SESSIONS_KEY, {});

        const token = await createSession(env, username);
        return new Response(JSON.stringify({ success: true }), { headers: sessionHeaders(token) });
    }

    if (path === '/api/login' && method === 'POST') {
        if (!isInitialized) return json({ success: false, msg: '系统尚未初始化' }, 400);

        const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
        const failKey = '.sys_fail_' + ip.replace(/[^0-9a-zA-Z.:_-]/g, '');
        const fail = (await getJson(failKey)) || { count: 0, until: 0 };

        if (fail.until && Date.now() < fail.until) {
            const mins = Math.ceil((fail.until - Date.now()) / 60000);
            return json({ success: false, msg: '尝试次数过多，请 ' + mins + ' 分钟后再试' }, 429);
        }

        let data;
        try { data = await request.json(); } catch (e) { return json({ success: false, msg: '请求格式错误' }, 400); }

        const ok = String(data.username || '') === config.username
            && await verifyPassword(config, String(data.password || ''));

        if (ok) {
            ctx.waitUntil(env.MY_BUCKET.delete(failKey));
            const token = await createSession(env, config.username);
            return new Response(JSON.stringify({ success: true }), { headers: sessionHeaders(token) });
        }

        fail.count = (fail.count || 0) + 1;
        if (fail.count >= LOGIN_MAX_FAILS) { fail.until = Date.now() + LOGIN_LOCK_MS; fail.count = 0; }
        ctx.waitUntil(saveJson(failKey, fail));
        return json({ success: false, msg: '用户名或密码错误' }, 401);
    }

    // 登录态查询：未鉴权也可访问，供前端判断是否展示登录页
    if (path === '/api/session' && method === 'GET') {
        const authed = await checkAuth(request.headers.get('Cookie'), config, env);
        return json({ authed, username: authed ? config.username : null, initialized: isInitialized });
    }

    const cookie = request.headers.get('Cookie');
    const authValid = await checkAuth(cookie, config, env);

    if (!authValid) {
        if (path.startsWith('/api/')) return json({ error: 'unauthorized' }, 401);
        return html(getHtml(isInitialized));
    }

    if (path === '/api/logout' && method === 'POST') {
        const token = readCookie(cookie, SESSION_COOKIE);
        if (token) {
            const sessions = (await getJson(SESSIONS_KEY)) || {};
            delete sessions[token];
            await saveJson(SESSIONS_KEY, sessions);
        }
        return new Response(JSON.stringify({ success: true }), { headers: clearSessionHeaders() });
    }

    // ---------- 3. 业务 API ----------

    if (path === '/api/stats' && method === 'GET') {
        let totalSize = 0, count = 0, cursor, truncated = true;
        while (truncated) {
            const res = await env.MY_BUCKET.list({ cursor, limit: 1000 });
            truncated = res.truncated;
            cursor = res.cursor;
            for (const o of res.objects) {
                if (o.key.startsWith('.sys_')) continue;
                totalSize += o.size;
                count++;
            }
        }
        return json({ totalSize, count });
    }

    if (path === '/api/text-content' && method === 'GET') {
        const key = url.searchParams.get('key');
        if (!key) return json({ error: 'missing key' }, 400);
        const obj = await env.MY_BUCKET.get(key);
        if (!obj) return json({ error: 'not found' }, 404);
        return new Response(obj.body, { headers: { 'Content-Type': 'text/plain;charset=UTF-8', 'Cache-Control': 'no-store' } });
    }

    if (path === '/api/text-content' && method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return json({ error: 'bad request' }, 400); }
        const { key, content } = body;
        if (!key) return json({ error: 'missing key' }, 400);
        if (typeof content !== 'string') return json({ error: 'invalid content' }, 400);
        if (content.length > MAX_TEXT_SIZE) return json({ error: 'too large', msg: '文件超过 2MB，请下载后编辑' }, 413);
        await env.MY_BUCKET.put(key, content, { httpMetadata: { contentType: getMimeType(key) } });
        return json({ success: true });
    }

    if (path === '/api/files' && method === 'GET') {
        const prefix = url.searchParams.get('prefix') || '';
        const folders = [];
        const files = [];
        let cursor, truncated = true;
        while (truncated && folders.length + files.length < LIST_LIMIT) {
            const list = await env.MY_BUCKET.list({ prefix, delimiter: '/', cursor, limit: 1000 });
            truncated = list.truncated;
            cursor = list.cursor;
            for (const p of list.delimitedPrefixes) folders.push({ key: p, isFolder: true });
            for (const o of list.objects) {
                if (o.key.startsWith('.sys_') || o.key === prefix) continue;
                files.push({ key: o.key, size: o.size, uploaded: o.uploaded, isFolder: false });
            }
        }
        return json([...folders, ...files]);
    }

    if (path === '/api/folders/all' && method === 'GET') {
        const all = [];
        const scan = async (prefix, depth) => {
            if (depth > 12 || all.length > 2000) return;
            let cursor, truncated = true;
            while (truncated) {
                const res = await env.MY_BUCKET.list({ prefix, delimiter: '/', cursor, limit: 1000 });
                truncated = res.truncated;
                cursor = res.cursor;
                for (const p of res.delimitedPrefixes) {
                    if (p.startsWith('.sys_')) continue;
                    all.push(p);
                    await scan(p, depth + 1);
                }
            }
        };
        await scan('', 0);
        return json(all);
    }

    if (path === '/api/create-folder' && method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return json({ error: 'bad request' }, 400); }
        const name = String(body.folderName || '').trim().replace(/^\/+|\/+$/g, '');
        if (!name || name.includes('..')) return json({ error: 'invalid name', msg: '文件夹名不合法' }, 400);
        const fullPath = (body.currentPath || '') + name + '/';
        await env.MY_BUCKET.put(fullPath, new Uint8Array(0));
        return json({ success: true });
    }

    if (path === '/api/move' && method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return json({ error: 'bad request' }, 400); }
        const keys = Array.isArray(body.keys) ? body.keys : [];
        const targetFolder = body.targetFolder || '';
        const moved = [];
        for (const oldKey of keys) {
            const isFolder = oldKey.endsWith('/');
            const base = isFolder ? oldKey.slice(0, -1) : oldKey;
            const name = base.split('/').pop();
            const newKey = targetFolder + name + (isFolder ? '/' : '');
            if (oldKey === newKey) continue;
            if (isFolder && (newKey === oldKey || newKey.startsWith(oldKey))) continue;
            if (await relocate(env, oldKey, newKey)) {
                await remapReferences(env, oldKey, newKey);
                moved.push(oldKey);
            }
        }
        return json({ success: true, moved });
    }

    if (path === '/api/upload' && method === 'POST') {
        let formData;
        try { formData = await request.formData(); } catch (e) { return json({ error: 'bad request' }, 400); }
        const file = formData.get('file');
        if (!file || typeof file === 'string') return json({ error: 'no file' }, 400);
        const folder = formData.get('folder') || '';
        const relativePath = (formData.get('relativePath') || file.name).replace(/^\/+/, '');
        const fullKey = folder + relativePath;

        await env.MY_BUCKET.put(fullKey, file.stream(), { httpMetadata: { contentType: file.type || getMimeType(fullKey) } });
        try {
            let history = (await getJson(UPLOADS_KEY)) || [];
            if (!Array.isArray(history)) history = [];
            history.unshift({ name: fullKey, size: file.size, date: new Date().toISOString() });
            if (history.length > HISTORY_LIMIT) history = history.slice(0, HISTORY_LIMIT);
            await saveJson(UPLOADS_KEY, history);
        } catch (e) { /* 历史记录失败不影响上传 */ }
        return json({ success: true, key: fullKey });
    }

    if (path === '/api/rename' && method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return json({ error: 'bad request' }, 400); }
        const oldKey = body.oldKey;
        const newKey = body.newKey;
        if (!oldKey || !newKey || oldKey === newKey) return json({ success: true });
        if (newKey.includes('..')) return json({ error: 'invalid name', msg: '名称不合法' }, 400);
        const ok = await relocate(env, oldKey, newKey);
        if (ok) await remapReferences(env, oldKey, newKey);
        return json({ success: ok });
    }

    const moveToTrash = async (targetKey) => {
        const targets = [];
        if (targetKey.endsWith('/')) {
            let cursor, truncated = true;
            while (truncated) {
                const res = await env.MY_BUCKET.list({ prefix: targetKey, cursor, limit: 1000 });
                truncated = res.truncated;
                cursor = res.cursor;
                targets.push(...res.objects.map(o => o.key));
            }
        } else {
            targets.push(targetKey);
        }
        for (const key of targets) {
            const obj = await env.MY_BUCKET.get(key);
            if (!obj) continue;
            await env.MY_BUCKET.put(TRASH_PREFIX + key, obj.body, { httpMetadata: obj.httpMetadata });
            await env.MY_BUCKET.delete(key);
        }
    };

    if (path === '/api/delete-file' && method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return json({ error: 'bad request' }, 400); }
        if (!body.key) return json({ error: 'missing key' }, 400);
        await moveToTrash(body.key);
        return json({ success: true });
    }

    if (path === '/api/batch-delete' && method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return json({ error: 'bad request' }, 400); }
        for (const key of (Array.isArray(body.keys) ? body.keys : [])) await moveToTrash(key);
        return json({ success: true });
    }

    if (path === '/api/trash/list' && method === 'GET') {
        const files = [];
        let cursor, truncated = true;
        while (truncated && files.length < LIST_LIMIT) {
            const list = await env.MY_BUCKET.list({ prefix: TRASH_PREFIX, cursor, limit: 1000 });
            truncated = list.truncated;
            cursor = list.cursor;
            for (const o of list.objects) {
                files.push({
                    key: o.key,
                    originalPath: o.key.slice(TRASH_PREFIX.length),
                    size: o.size,
                    deletedAt: o.uploaded
                });
            }
        }
        files.sort((a, b) => new Date(b.deletedAt) - new Date(a.deletedAt));
        return json(files);
    }

    if (path === '/api/trash/restore' && method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return json({ error: 'bad request' }, 400); }
        for (const trashKey of (Array.isArray(body.keys) ? body.keys : [])) {
            if (!trashKey.startsWith(TRASH_PREFIX)) continue;
            const originalKey = trashKey.slice(TRASH_PREFIX.length);
            const obj = await env.MY_BUCKET.get(trashKey);
            if (!obj) continue;
            await env.MY_BUCKET.put(originalKey, obj.body, { httpMetadata: obj.httpMetadata });
            await env.MY_BUCKET.delete(trashKey);
        }
        return json({ success: true });
    }

    if (path === '/api/trash/delete' && method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return json({ error: 'bad request' }, 400); }
        const keys = (Array.isArray(body.keys) ? body.keys : []).filter(k => k.startsWith(TRASH_PREFIX));
        for (let i = 0; i < keys.length; i += 500) {
            await env.MY_BUCKET.delete(keys.slice(i, i + 500));
        }
        return json({ success: true });
    }

    if (path === '/api/uploads/history' && method === 'GET') {
        const history = (await getJson(UPLOADS_KEY)) || [];
        return json(Array.isArray(history) ? history : []);
    }

    if (path === '/api/uploads/clear-history' && method === 'POST') {
        await saveJson(UPLOADS_KEY, []);
        return json({ success: true });
    }

    if (path === '/api/shares' && method === 'GET') {
        const shares = (await getJson(SHARES_KEY)) || {};
        const list = Object.entries(shares).map(([token, info]) => ({ token, ...info }));
        list.sort((a, b) => new Date(b.created || 0) - new Date(a.created || 0));
        return json(list);
    }

    if (path === '/api/shares/create' && method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return json({ error: 'bad request' }, 400); }
        if (!body.path) return json({ error: 'missing path' }, 400);
        const shares = (await getJson(SHARES_KEY)) || {};
        const token = randomHex(8);
        const shareData = { path: body.path, created: new Date().toISOString(), views: 0 };
        if (body.password) shareData.password = String(body.password);
        if (body.maxViews) shareData.maxViews = parseInt(body.maxViews, 10) || undefined;
        if (body.expireHours) shareData.expireTime = Date.now() + parseInt(body.expireHours, 10) * 3600000;
        shares[token] = shareData;
        await saveJson(SHARES_KEY, shares);
        return json({ success: true, token });
    }

    if (path === '/api/shares/delete' && method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return json({ error: 'bad request' }, 400); }
        const shares = (await getJson(SHARES_KEY)) || {};
        delete shares[body.token];
        await saveJson(SHARES_KEY, shares);
        return json({ success: true });
    }

    if (path === '/api/shares/batch-delete' && method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return json({ error: 'bad request' }, 400); }
        const shares = (await getJson(SHARES_KEY)) || {};
        for (const t of (Array.isArray(body.tokens) ? body.tokens : [])) delete shares[t];
        await saveJson(SHARES_KEY, shares);
        return json({ success: true });
    }

    if (path.startsWith('/file/')) {
        const key = decodeURIComponent(path.slice(6).split('?')[0]);
        if (!key || key.startsWith('.sys_')) return new Response('404', { status: 404 });

        const getOpts = {};
        const rangeHeader = request.headers.get('Range');
        const ifMatchHeader = request.headers.get('if-match');
        if (rangeHeader) getOpts.range = rangeHeader;
        if (ifMatchHeader) getOpts.onlyIf = { etag: ifMatchHeader };

        const object = await env.MY_BUCKET.get(key, getOpts);
        if (!object) return new Response('404', { status: 404 });

        const headers = new Headers(SECURE_HEADERS);
        object.writeHttpMetadata(headers);
        headers.set('etag', object.httpEtag);

        if (range && object.range) {
            headers.set('content-range', 'bytes ' + object.range.offset + '-' + object.range.end + '/' + object.size);
            headers.set('content-length', String(object.range.end - object.range.offset + 1));
            return new Response(object.body, { headers, status: 206 });
        }

        const shortName = key.split('/').pop();
        const mode = url.searchParams.get('mode');
        const ct = (headers.get('content-type') || '').toLowerCase();
        const forceDownload = mode === 'download' || isExecutableType(ct) || isExecutableExtension(shortName);
        headers.set('Content-Disposition', contentDisposition(shortName, forceDownload));
        return new Response(object.body, { headers });
    }

    if (path === '/api/settings/password' && method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return json({ error: 'bad request' }, 400); }
        const password = String(body.password || '');
        if (password.length < 6) return json({ success: false, msg: '密码至少 6 位' }, 400);
        const salt = config.salt || randomHex(16);
        config.salt = salt;
        config.password = await hashText(salt + password);
        await saveJson(CONFIG_KEY, config);
        await saveJson(SESSIONS_KEY, {});
        const token = await createSession(env, config.username);
        return new Response(JSON.stringify({ success: true }), { headers: sessionHeaders(token) });
    }

    return html(getHtml(isInitialized));
}

// ---------- 存储与工具 ----------

async function readJson(env, key) {
    const obj = await env.MY_BUCKET.get(key);
    if (!obj) return null;
    try { return await obj.json(); } catch (e) { return null; }
}

async function writeJson(env, key, data) {
    await env.MY_BUCKET.put(key, JSON.stringify(data), { httpMetadata: { contentType: 'application/json' } });
}

function randomHex(bytes) {
    const arr = crypto.getRandomValues(new Uint8Array(bytes));
    let out = '';
    for (const b of arr) out += b.toString(16).padStart(2, '0');
    return out;
}

async function hashText(text) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    let out = '';
    for (const b of new Uint8Array(buf)) out += b.toString(16).padStart(2, '0');
    return out;
}

function safeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
}

async function verifyPassword(config, input) {
    if (!config || !config.password) return false;
    if (config.salt) return safeEqual(await hashText(config.salt + input), config.password);
    return safeEqual(await hashText(input), config.password);
}

async function createSession(env, username) {
    const token = randomHex(32);
    const sessions = (await readJson(env, SESSIONS_KEY)) || {};
    const now = Date.now();
    for (const k of Object.keys(sessions)) {
        if (!sessions[k] || !sessions[k].exp || sessions[k].exp < now) delete sessions[k];
    }
    sessions[token] = { u: username, exp: now + SESSION_TTL };
    await writeJson(env, SESSIONS_KEY, sessions);
    return token;
}

function sessionHeaders(token) {
    return {
        'Content-Type': 'application/json;charset=UTF-8',
        'Cache-Control': 'no-store',
        'Set-Cookie': SESSION_COOKIE + '=' + token + '; Path=/; Max-Age=' + Math.floor(SESSION_TTL / 1000) + '; HttpOnly; SameSite=Strict; Secure'
    };
}

function clearSessionHeaders() {
    return {
        'Content-Type': 'application/json;charset=UTF-8',
        'Cache-Control': 'no-store',
        'Set-Cookie': SESSION_COOKIE + '=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict; Secure'
    };
}

function readCookie(cookieStr, name) {
    if (!cookieStr) return null;
    for (const part of cookieStr.split(';')) {
        const idx = part.indexOf('=');
        if (idx === -1) continue;
        if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim();
    }
    return null;
}

async function checkAuth(cookieStr, config, env) {
    if (!cookieStr || !config) return false;
    const token = readCookie(cookieStr, SESSION_COOKIE);
    if (!token || !/^[a-f0-9]{64}$/.test(token)) return false;
    const sessions = (await readJson(env, SESSIONS_KEY)) || {};
    const rec = sessions[token];
    if (!rec || !rec.exp || rec.exp < Date.now()) return false;
    return rec.u === config.username;
}

async function relocate(env, oldKey, newKey) {
    if (oldKey.endsWith('/')) {
        const objects = [];
        let cursor, truncated = true;
        while (truncated && objects.length < LIST_LIMIT) {
            const res = await env.MY_BUCKET.list({ prefix: oldKey, cursor, limit: 1000 });
            truncated = res.truncated;
            cursor = res.cursor;
            objects.push(...res.objects);
        }
        for (const o of objects) {
            const target = newKey + o.key.slice(oldKey.length);
            const src = await env.MY_BUCKET.get(o.key);
            if (!src) continue;
            await env.MY_BUCKET.put(target, src.body, { httpMetadata: src.httpMetadata });
            await env.MY_BUCKET.delete(o.key);
        }
        return true;
    }
    const obj = await env.MY_BUCKET.get(oldKey);
    if (!obj) return false;
    await env.MY_BUCKET.put(newKey, obj.body, { httpMetadata: obj.httpMetadata });
    await env.MY_BUCKET.delete(oldKey);
    return true;
}

async function remapReferences(env, oldKey, newKey) {
    const isFolder = oldKey.endsWith('/');
    const remap = (value) => {
        if (!value) return value;
        if (value === oldKey) return newKey;
        if (isFolder && value.startsWith(oldKey)) return newKey + value.slice(oldKey.length);
        return value;
    };

    const shares = (await readJson(env, SHARES_KEY)) || {};
    let changed = false;
    for (const k of Object.keys(shares)) {
        const next = remap(shares[k].path);
        if (next !== shares[k].path) { shares[k].path = next; changed = true; }
    }
    if (changed) await writeJson(env, SHARES_KEY, shares);

    let history = (await readJson(env, UPLOADS_KEY)) || [];
    if (!Array.isArray(history)) return;
    let hChanged = false;
    for (const h of history) {
        const next = remap(h.name);
        if (next !== h.name) { h.name = next; hChanged = true; }
    }
    if (hChanged) await writeJson(env, UPLOADS_KEY, history);
}

function contentDisposition(fileName, asAttachment) {
    const ascii = String(fileName).replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
    const encoded = encodeURIComponent(fileName);
    return (asAttachment ? 'attachment' : 'inline') + '; filename="' + ascii + '"; filename*=UTF-8\'\'' + encoded;
}

function isExecutableType(contentType) {
    const ct = (contentType || '').toLowerCase();
    return ct.indexOf('html') !== -1 || ct.indexOf('svg') !== -1 || ct.indexOf('xml') !== -1
        || ct.indexOf('javascript') !== -1 || ct.indexOf('x-shockwave') !== -1;
}

// 上传时上报的 MIME 不可信，扩展名兜底
function isExecutableExtension(fileName) {
    const ext = String(fileName || '').split('.').pop().toLowerCase();
    return ['html', 'htm', 'xhtml', 'xht', 'shtml', 'svg', 'xml', 'xsl', 'js', 'mjs', 'cjs',
            'jsx', 'ts', 'tsx', 'vbs', 'hta', 'swf', 'jar'].indexOf(ext) !== -1;
}

function escapeHtml(value) {
    return String(value === null || value === undefined ? '' : value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function getMimeType(key) {
    const ext = String(key).split('.').pop().toLowerCase();
    const map = {
        txt: 'text/plain;charset=UTF-8', html: 'text/html;charset=UTF-8', htm: 'text/html;charset=UTF-8',
        css: 'text/css;charset=UTF-8', js: 'application/javascript;charset=UTF-8', mjs: 'application/javascript;charset=UTF-8',
        json: 'application/json;charset=UTF-8', xml: 'application/xml;charset=UTF-8', md: 'text/markdown;charset=UTF-8',
        markdown: 'text/markdown;charset=UTF-8', csv: 'text/csv;charset=UTF-8', yml: 'text/yaml;charset=UTF-8',
        yaml: 'text/yaml;charset=UTF-8', toml: 'text/plain;charset=UTF-8', log: 'text/plain;charset=UTF-8',
        svg: 'image/svg+xml'
    };
    return map[ext] || 'application/octet-stream';
}

// ---------- 公开页面 ----------

function pageShell(title, body) {
    return '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8">'
        + '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
        + '<meta name="theme-color" content="#4f46e5">'
        + '<title>' + escapeHtml(title) + '</title>'
        + '<script src="https://cdn.tailwindcss.com"><\/script>'
        + '<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">'
        + '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">'
        + '<style>body{font-family:"Inter",system-ui,sans-serif}</style></head>'
        + '<body class="m-0 bg-slate-50 antialiased">' + body + '</body></html>';
}

function getErrorPageHtml(title, msg) {
    const body = '<div class="flex min-h-screen items-center justify-center p-4">'
        + '<div class="w-full max-w-sm rounded-3xl border border-slate-100 bg-white p-10 text-center shadow-lg shadow-slate-200/60">'
        + '<div class="mx-auto mb-5 flex h-16 w-16 items-center justify-center rounded-2xl bg-slate-50 text-2xl text-slate-300">'
        + '<i class="fa-regular fa-face-frown"></i></div>'
        + '<h1 class="mb-2 text-lg font-semibold text-slate-800">' + escapeHtml(title) + '</h1>'
        + '<p class="text-sm leading-relaxed text-slate-500">' + escapeHtml(msg) + '</p>'
        + '</div></div>';
    return pageShell(title, body);
}

function getPasswordPageHtml(token, isWrong) {
    const body = '<div class="flex min-h-screen items-center justify-center p-4">'
        + '<div class="w-full max-w-sm overflow-hidden rounded-3xl border border-slate-100 bg-white shadow-lg shadow-slate-200/60">'
        + '<div class="border-b border-slate-100 bg-slate-50/70 px-8 py-7 text-center">'
        + '<div class="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-2xl bg-indigo-50 text-indigo-500 text-lg">'
        + '<i class="fa-solid fa-lock"></i></div>'
        + '<h1 class="text-base font-semibold text-slate-800">该文件已加密</h1>'
        + '<p class="mt-1 text-xs text-slate-500">请输入访问密码以继续</p></div>'
        + '<form action="/s/' + encodeURIComponent(token) + '" method="GET" class="p-8">'
        + '<label class="mb-1.5 block text-xs font-medium text-slate-500">访问密码</label>'
        + '<input type="password" name="pwd" required placeholder="请输入密码" autocomplete="off" autofocus '
        + 'class="h-11 w-full rounded-xl border bg-slate-50 px-4 text-sm outline-none transition '
        + (isWrong ? 'border-red-300 ring-4 ring-red-500/10' : 'border-slate-200 focus:border-indigo-400 focus:bg-white focus:ring-4 focus:ring-indigo-500/10') + '">'
        + (isWrong ? '<p class="mt-2 flex items-center gap-1.5 text-xs font-medium text-red-500"><i class="fa-solid fa-circle-exclamation"></i>密码错误，请重试</p>' : '')
        + '<button type="submit" class="mt-5 h-11 w-full rounded-xl bg-slate-900 text-sm font-semibold text-white transition hover:bg-slate-800 active:scale-[.98]">查看文件</button>'
        + '</form></div></div>';
    return pageShell('文件已加密', body);
}

function getSharePageHtml(fileName, size, token, type, password) {
    const ct = (type || '').toLowerCase();
    const isImage = ct.startsWith('image/') && !ct.includes('svg');
    const isVideo = ct.startsWith('video/');
    const safeName = escapeHtml(fileName);
    const pwdParam = password ? '&pwd=' + encodeURIComponent(password) : '';
    const icon = isImage ? 'fa-regular fa-image' : (isVideo ? 'fa-regular fa-file-video' : 'fa-regular fa-file');

    let preview = '';
    if (isImage) {
        preview = '<div class="mb-6 flex items-center justify-center overflow-hidden rounded-2xl border border-slate-200 bg-slate-100">'
            + '<img src="/s/' + encodeURIComponent(token) + '?mode=inline' + pwdParam + '" alt="' + safeName + '" class="max-h-64 max-w-full object-contain"></div>';
    } else if (isVideo) {
        preview = '<div class="mb-6 overflow-hidden rounded-2xl bg-black shadow-inner">'
            + '<video src="/s/' + encodeURIComponent(token) + '?mode=inline' + pwdParam + '" controls class="max-h-64 w-full"></video></div>';
    }

    const body = '<div class="flex min-h-screen items-center justify-center p-4">'
        + '<div class="w-full max-w-md overflow-hidden rounded-3xl border border-slate-100 bg-white shadow-lg shadow-slate-200/60">'
        + '<div class="p-8 text-center">'
        + '<div class="mx-auto mb-5 flex h-16 w-16 items-center justify-center rounded-2xl bg-indigo-50 text-2xl text-indigo-500"><i class="' + icon + '"></i></div>'
        + '<h1 class="truncate px-2 text-base font-semibold text-slate-800" title="' + safeName + '">' + safeName + '</h1>'
        + '<p class="mt-1.5 text-xs font-medium uppercase tracking-wide text-slate-400">' + formatBytes(size) + '</p>'
        + '</div>'
        + '<div class="px-8 pb-8">' + preview
        + '<a href="/s/' + encodeURIComponent(token) + '?mode=download' + pwdParam + '" '
        + 'class="flex h-12 w-full items-center justify-center gap-2 rounded-xl bg-slate-900 text-sm font-semibold text-white transition hover:bg-slate-800 active:scale-[.98]">'
        + '<i class="fa-solid fa-download"></i>立即下载</a>'
        + '<p class="mt-6 text-center text-[11px] font-medium tracking-wide text-slate-300">SECURE FILE TRANSFER</p>'
        + '</div></div></div>';
    return pageShell(fileName, body);
}

function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const k = 1024;
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), 4);
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + ['B', 'KB', 'MB', 'GB', 'TB'][i];
}
