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

function getHtml(isInitialized) {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="theme-color" content="#4f46e5">
    <title>Cloud Space</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/vue/3.3.4/vue.global.prod.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    fontFamily: { sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'] },
                    boxShadow: {
                        soft: '0 1px 2px 0 rgba(15,23,42,0.04), 0 1px 3px 0 rgba(15,23,42,0.06)',
                        card: '0 4px 16px -4px rgba(15,23,42,0.08), 0 2px 6px -2px rgba(15,23,42,0.04)',
                        pop: '0 16px 40px -12px rgba(15,23,42,0.18), 0 4px 12px -4px rgba(15,23,42,0.08)'
                    },
                    borderRadius: { '4xl': '28px' }
                }
            }
        }
    </script>
    <style>
        * { -webkit-tap-highlight-color: transparent; }
        html, body { height: 100%; }
        ::-webkit-scrollbar { width: 0px; height: 0px; background: transparent; }
        .scroll-thin::-webkit-scrollbar { width: 6px; height: 6px; }
        .scroll-thin::-webkit-scrollbar-track { background: transparent; }
        .scroll-thin::-webkit-scrollbar-thumb { background: rgba(100,116,139,0.25); border-radius: 999px; }
        .scroll-thin::-webkit-scrollbar-thumb:hover { background: rgba(100,116,139,0.4); }

        .nav-item { transition: background-color .18s ease, color .18s ease; }
        .nav-item .nav-bar { transform: scaleY(0); transition: transform .18s cubic-bezier(.4,0,.2,1); }
        .nav-item.is-active .nav-bar { transform: scaleY(1); }

        input[type="checkbox"].cbx {
            appearance: none; width: 18px; height: 18px; border-radius: 5px;
            border: 1.5px solid #cbd5e1; background: #fff; cursor: pointer;
            position: relative; transition: all .15s ease; flex: none;
        }
        input[type="checkbox"].cbx:hover { border-color: #94a3b8; }
        input[type="checkbox"].cbx:checked { background: #4f46e5; border-color: #4f46e5; }
        input[type="checkbox"].cbx:checked::after {
            content: '\\\\f00c'; font-family: 'Font Awesome 6 Free'; font-weight: 900;
            color: #fff; font-size: 10px; position: absolute; top: 50%; left: 50%;
            transform: translate(-50%, -50%);
        }

        .ctx { position: fixed; z-index: 5000; min-width: 190px; padding: 6px;
               background: rgba(255,255,255,.92); backdrop-filter: blur(18px); -webkit-backdrop-filter: blur(18px);
               border-radius: 14px; border: 1px solid rgba(15,23,42,.06);
               box-shadow: 0 16px 40px -12px rgba(15,23,42,.22), 0 4px 12px -4px rgba(15,23,42,.1);
               animation: pop .14s cubic-bezier(.16,1,.3,1); transform-origin: top left; }
        .ctx-item { display: flex; align-items: center; gap: 11px; padding: 9px 12px; border-radius: 9px;
                    font-size: 13.5px; font-weight: 500; color: #334155; cursor: pointer; transition: background-color .12s ease; }
        .ctx-item i { width: 16px; text-align: center; font-size: 13px; }
        .ctx-item:hover { background: #f1f5f9; }
        .ctx-item.is-danger { color: #dc2626; }
        .ctx-item.is-danger:hover { background: #fef2f2; }
        .ctx-sep { height: 1px; background: rgba(15,23,42,.06); margin: 5px 8px; }

        .card-hover { transition: transform .22s cubic-bezier(.25,.8,.25,1), box-shadow .22s ease, border-color .22s ease; }
        .card-hover:hover { transform: translateY(-3px); box-shadow: 0 12px 28px -10px rgba(15,23,42,.16); }

        .fade-enter-active, .fade-leave-active { transition: opacity .18s ease; }
        .fade-enter-from, .fade-leave-to { opacity: 0; }
        .pop-enter-active { transition: all .28s cubic-bezier(.16,1,.3,1); }
        .pop-leave-active { transition: all .16s ease; }
        .pop-enter-from, .pop-leave-to { opacity: 0; transform: scale(.96) translateY(8px); }
        .rise-enter-active, .rise-leave-active { transition: all .32s cubic-bezier(.16,1,.3,1); }
        .rise-enter-from, .rise-leave-to { transform: translateY(120%); opacity: 0; }

        @keyframes pop { from { opacity: 0; transform: scale(.95); } to { opacity: 1; transform: scale(1); } }
        @keyframes floaty { 0%,100% { transform: translate3d(0,0,0); } 50% { transform: translate3d(0,-16px,0); } }
        @keyframes shimmer { 100% { transform: translateX(100%); } }
        .skel { position: relative; overflow: hidden; background: #eef2f7; }
        .skel::after { content: ''; position: absolute; inset: 0; transform: translateX(-100%);
                       background: linear-gradient(90deg, transparent, rgba(255,255,255,.7), transparent);
                       animation: shimmer 1.4s infinite; }
        .prose-custom h1 { font-size: 1.5em; font-weight: 600; margin: .8em 0 .4em; }
        .prose-custom h2 { font-size: 1.22em; font-weight: 600; margin: .8em 0 .4em; }
        .prose-custom h3 { font-size: 1.06em; font-weight: 600; margin: .7em 0 .3em; }
        .prose-custom p { margin: .55em 0; line-height: 1.75; }
        .prose-custom ul { list-style: disc; padding-left: 1.4em; margin: .55em 0; }
        .prose-custom ol { list-style: decimal; padding-left: 1.4em; margin: .55em 0; }
        .prose-custom blockquote { border-left: 3px solid #c7d2fe; padding-left: .9em; color: #64748b; margin: .7em 0; }
        .prose-custom pre { background: #0f172a; color: #e2e8f0; padding: .9em 1em; border-radius: 10px; overflow-x: auto; margin: .7em 0; }
        .prose-custom code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #f1f5f9;
                             padding: .12em .38em; border-radius: 5px; font-size: .88em; }
        .prose-custom pre code { background: transparent; padding: 0; color: inherit; }
        .prose-custom a { color: #4f46e5; text-decoration: underline; text-underline-offset: 2px; }
        .prose-custom table { border-collapse: collapse; margin: .7em 0; }
        .prose-custom th, .prose-custom td { border: 1px solid #e2e8f0; padding: .4em .7em; }
        [v-cloak] { display: none; }
    </style>
</head>
<body class="bg-slate-50 text-slate-700 antialiased">
<div id="app" v-cloak class="h-full" @click="closeContextMenu" @contextmenu="closeContextMenu">

    <transition name="fade">
    <div v-if="!isLoggedIn" class="fixed inset-0 z-50 flex items-center justify-center overflow-hidden bg-slate-50 p-4">
        <div class="pointer-events-none absolute inset-0 overflow-hidden">
            <div class="absolute -top-40 -left-32 h-[420px] w-[420px] rounded-full bg-indigo-300/35 blur-[110px]"></div>
            <div class="absolute -bottom-44 -right-24 h-[460px] w-[460px] rounded-full bg-sky-300/35 blur-[110px]"></div>
            <div class="absolute left-1/2 top-1/3 h-[300px] w-[300px] -translate-x-1/2 rounded-full bg-violet-200/40 blur-[100px]" style="animation: floaty 9s ease-in-out infinite"></div>
        </div>

        <div class="relative z-10 w-full max-w-[380px]">
            <div class="rounded-4xl border border-white/70 bg-white/80 p-8 shadow-pop backdrop-blur-2xl">
                <div class="mb-8 text-center">
                    <div class="mx-auto mb-5 flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-600 text-xl text-white shadow-lg shadow-indigo-500/30">
                        <i class="fa-solid fa-cloud"></i>
                    </div>
                    <h1 class="text-[22px] font-semibold tracking-tight text-slate-900">{{ !serverInitialized ? '初始化系统' : 'Cloud Space' }}</h1>
                    <p class="mt-1.5 text-sm text-slate-500">{{ !serverInitialized ? '创建您的管理员账户' : '登录以进入私有云空间' }}</p>
                </div>

                <form @submit.prevent="handleAuth" class="space-y-4">
                    <div>
                        <label class="mb-1.5 block text-xs font-medium text-slate-500">用户名</label>
                        <div class="relative">
                            <i class="fa-regular fa-user pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-sm text-slate-400"></i>
                            <input v-model="authForm.username" type="text" autocomplete="username" placeholder="请输入用户名"
                                   class="h-12 w-full rounded-xl border border-slate-200 bg-white pl-11 pr-4 text-sm text-slate-800 outline-none transition placeholder:text-slate-400 focus:border-indigo-400 focus:ring-4 focus:ring-indigo-500/10" required>
                        </div>
                    </div>
                    <div>
                        <label class="mb-1.5 block text-xs font-medium text-slate-500">密码</label>
                        <div class="relative">
                            <i class="fa-solid fa-lock pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-sm text-slate-400"></i>
                            <input v-model="authForm.password" type="password" autocomplete="current-password" placeholder="请输入密码"
                                   class="h-12 w-full rounded-xl border border-slate-200 bg-white pl-11 pr-4 text-sm text-slate-800 outline-none transition placeholder:text-slate-400 focus:border-indigo-400 focus:ring-4 focus:ring-indigo-500/10" required>
                        </div>
                    </div>

                    <p v-if="authError" class="flex items-center gap-2 rounded-xl bg-red-50 px-3.5 py-2.5 text-xs font-medium text-red-600">
                        <i class="fa-solid fa-circle-exclamation"></i><span>{{ authError }}</span>
                    </p>

                    <button type="submit" :disabled="authLoading"
                            class="flex h-12 w-full items-center justify-center gap-2 rounded-xl bg-slate-900 text-sm font-semibold text-white transition hover:bg-slate-800 active:scale-[.98] disabled:opacity-60">
                        <i v-if="authLoading" class="fa-solid fa-circle-notch fa-spin"></i>
                        <span>{{ authLoading ? '处理中…' : (!serverInitialized ? '完成初始化' : '登 录') }}</span>
                    </button>
                </form>

                <p class="mt-6 text-center text-[11px] leading-relaxed text-slate-400">
                    {{ !serverInitialized ? '密码至少 6 位，请妥善保管' : '受 Cloudflare R2 加密存储保护' }}
                </p>
            </div>
        </div>
    </div>
    </transition>

    <div v-if="isLoggedIn" class="flex h-full w-full">

        <div v-if="mobileMenuOpen" @click.stop="mobileMenuOpen = false"
             class="fixed inset-0 z-30 bg-slate-900/40 backdrop-blur-sm transition-opacity md:hidden"></div>

        <aside :class="['fixed z-40 flex h-full w-[264px] flex-none flex-col border-r border-slate-200/80 bg-white transition-transform duration-300 ease-out md:static md:translate-x-0',
                        mobileMenuOpen ? 'translate-x-0' : '-translate-x-full']" @click.stop>
            <div class="flex items-center gap-3 px-5 py-5">
                <div class="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-indigo-500 to-violet-600 text-white shadow-md shadow-indigo-500/25">
                    <i class="fa-solid fa-cloud text-sm"></i>
                </div>
                <div class="min-w-0">
                    <div class="truncate text-[15px] font-semibold leading-tight text-slate-900">Cloud Space</div>
                    <div class="text-[11px] leading-tight text-slate-400">R2 私有云盘</div>
                </div>
            </div>

            <nav class="scroll-thin flex-1 space-y-1 overflow-y-auto px-3 pb-4">
                <div class="px-3 pb-2 pt-3 text-[10px] font-semibold uppercase tracking-[.12em] text-slate-400">存储</div>

                <div @click="switchView('uploads')" :class="['nav-item relative flex cursor-pointer items-center gap-3 rounded-xl px-3 py-2.5 text-sm', currentView === 'uploads' ? 'is-active bg-indigo-50 font-semibold text-indigo-600' : 'font-medium text-slate-600 hover:bg-slate-50']">
                    <span class="nav-bar absolute left-0 top-1/2 h-5 w-[3px] -translate-y-1/2 rounded-r bg-indigo-500"></span>
                    <i class="fa-solid fa-cloud-arrow-up w-4 text-center"></i>
                    <span>传输中心</span>
                    <span v-if="activeUploadCount > 0" class="ml-auto rounded-md bg-indigo-500 px-1.5 py-0.5 text-[10px] font-semibold text-white">{{ activeUploadCount }}</span>
                </div>

                <div @click="switchView('files')" :class="['nav-item relative flex cursor-pointer items-center gap-3 rounded-xl px-3 py-2.5 text-sm', currentView === 'files' ? 'is-active bg-indigo-50 font-semibold text-indigo-600' : 'font-medium text-slate-600 hover:bg-slate-50']">
                    <span class="nav-bar absolute left-0 top-1/2 h-5 w-[3px] -translate-y-1/2 rounded-r bg-indigo-500"></span>
                    <i class="fa-regular fa-folder-open w-4 text-center"></i>
                    <span>全部文件</span>
                </div>

                <div @click="switchView('shares')" :class="['nav-item relative flex cursor-pointer items-center gap-3 rounded-xl px-3 py-2.5 text-sm', currentView === 'shares' ? 'is-active bg-indigo-50 font-semibold text-indigo-600' : 'font-medium text-slate-600 hover:bg-slate-50']">
                    <span class="nav-bar absolute left-0 top-1/2 h-5 w-[3px] -translate-y-1/2 rounded-r bg-indigo-500"></span>
                    <i class="fa-solid fa-share-nodes w-4 text-center"></i>
                    <span>分享管理</span>
                </div>

                <div @click="switchView('trash')" :class="['nav-item relative flex cursor-pointer items-center gap-3 rounded-xl px-3 py-2.5 text-sm', currentView === 'trash' ? 'is-active bg-indigo-50 font-semibold text-indigo-600' : 'font-medium text-slate-600 hover:bg-slate-50']">
                    <span class="nav-bar absolute left-0 top-1/2 h-5 w-[3px] -translate-y-1/2 rounded-r bg-indigo-500"></span>
                    <i class="fa-solid fa-trash-can-arrow-up w-4 text-center"></i>
                    <span>回收站</span>
                    <span v-if="trashFiles.length > 0" class="ml-auto text-[10px] font-medium text-slate-400">{{ trashFiles.length }}</span>
                </div>

                <div class="px-3 pb-2 pt-5 text-[10px] font-semibold uppercase tracking-[.12em] text-slate-400">系统</div>

                <div @click="switchView('settings')" :class="['nav-item relative flex cursor-pointer items-center gap-3 rounded-xl px-3 py-2.5 text-sm', currentView === 'settings' ? 'is-active bg-indigo-50 font-semibold text-indigo-600' : 'font-medium text-slate-600 hover:bg-slate-50']">
                    <span class="nav-bar absolute left-0 top-1/2 h-5 w-[3px] -translate-y-1/2 rounded-r bg-indigo-500"></span>
                    <i class="fa-solid fa-sliders w-4 text-center"></i>
                    <span>系统设置</span>
                </div>
            </nav>

            <div class="border-t border-slate-100 p-3">
                <div class="flex items-center gap-3 rounded-xl bg-slate-50 px-3 py-2.5">
                    <div class="flex h-8 w-8 flex-none items-center justify-center rounded-full bg-gradient-to-br from-slate-700 to-slate-900 text-[11px] font-semibold text-white">
                        {{ (username || 'A').slice(0, 1).toUpperCase() }}
                    </div>
                    <div class="min-w-0 flex-1">
                        <div class="truncate text-[13px] font-medium text-slate-800">{{ username || '管理员' }}</div>
                        <div class="flex items-center gap-1.5 text-[11px] text-slate-400">
                            <span class="h-1.5 w-1.5 rounded-full bg-emerald-500"></span>已连接
                        </div>
                    </div>
                    <button @click="logout" title="退出登录" class="flex h-8 w-8 flex-none items-center justify-center rounded-lg text-slate-400 transition hover:bg-white hover:text-slate-700">
                        <i class="fa-solid fa-arrow-right-from-bracket text-xs"></i>
                    </button>
                </div>
            </div>
        </aside>

        <main class="flex h-full min-w-0 flex-1 flex-col bg-slate-50">

            <div class="sticky top-0 z-20 flex items-center gap-3 border-b border-slate-200/80 bg-white/85 px-4 py-3 backdrop-blur-xl md:hidden" @click.stop>
                <button @click="mobileMenuOpen = true" class="flex h-9 w-9 items-center justify-center rounded-xl border border-slate-200 text-slate-600">
                    <i class="fa-solid fa-bars text-sm"></i>
                </button>
                <span class="text-sm font-semibold text-slate-800">{{ viewTitle }}</span>
            </div>

            <div class="scroll-thin flex-1 overflow-y-auto px-4 py-6 md:px-8 md:py-8">

                <div v-if="loading" class="mx-auto max-w-6xl space-y-4">
                    <div class="skel h-8 w-52 rounded-xl"></div>
                    <div class="skel h-[132px] rounded-2xl"></div>
                    <div class="skel h-[280px] rounded-2xl"></div>
                </div>

                <div v-else-if="currentView === 'uploads'" class="mx-auto max-w-5xl space-y-8" @click.stop>
                    <div>
                        <h1 class="text-xl font-semibold tracking-tight text-slate-900">传输中心</h1>
                        <p class="mt-1 text-sm text-slate-500">上传文件或整个文件夹，当前目标目录
                            <span class="rounded-md bg-indigo-50 px-1.5 py-0.5 font-medium text-indigo-600">{{ currentPath || '根目录' }}</span>
                        </p>
                    </div>

                    <div @dragover.prevent="dragActive = true" @dragleave.prevent="dragActive = false" @drop.prevent="handleDrop"
                         :class="['group relative cursor-pointer overflow-hidden rounded-4xl border-2 border-dashed px-8 py-14 text-center transition-all duration-200',
                                  dragActive ? 'border-indigo-400 bg-indigo-50/70' : 'border-slate-200 bg-white hover:border-indigo-300 hover:bg-indigo-50/30']"
                         @click="pickFiles">
                        <div class="pointer-events-none relative z-10">
                            <div :class="['mx-auto mb-5 flex h-16 w-16 items-center justify-center rounded-2xl text-2xl transition-all duration-300',
                                          dragActive ? 'scale-110 bg-indigo-500 text-white shadow-lg shadow-indigo-500/30' : 'bg-indigo-50 text-indigo-500 group-hover:scale-105']">
                                <i class="fa-solid fa-cloud-arrow-up"></i>
                            </div>
                            <p class="text-[15px] font-semibold text-slate-800">{{ dragActive ? '松开即可上传' : '拖拽文件或文件夹到此处' }}</p>
                            <p class="mt-1.5 text-sm text-slate-500">也可以点击选择文件，文件夹会自动保留目录结构</p>
                            <div class="pointer-events-auto mt-6 flex flex-wrap items-center justify-center gap-2.5" @click.stop>
                                <button @click="pickFiles" class="flex h-9 items-center gap-2 rounded-xl bg-slate-900 px-4 text-[13px] font-medium text-white transition hover:bg-slate-800 active:scale-95">
                                    <i class="fa-regular fa-file text-xs"></i>选择文件
                                </button>
                                <button @click="pickFolder" class="flex h-9 items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 text-[13px] font-medium text-slate-700 transition hover:border-slate-300 hover:bg-slate-50 active:scale-95">
                                    <i class="fa-regular fa-folder text-xs"></i>选择文件夹
                                </button>
                            </div>
                        </div>
                    </div>

                    <div v-if="uploadQueue.length > 0">
                        <div class="mb-3 flex items-center justify-between">
                            <h2 class="text-sm font-semibold text-slate-800">上传队列
                                <span class="ml-1 font-normal text-slate-400">{{ activeUploadCount }} 个进行中</span>
                            </h2>
                            <button v-if="activeUploadCount === 0" @click="clearQueue" class="text-[13px] font-medium text-slate-500 transition hover:text-indigo-600">清空列表</button>
                        </div>
                        <div class="space-y-2.5">
                            <div v-for="item in uploadQueue" :key="item.id" class="flex items-center gap-4 rounded-2xl border border-slate-100 bg-white p-4 shadow-soft">
                                <div :class="['flex h-10 w-10 flex-none items-center justify-center rounded-xl text-sm',
                                              item.status === 'success' ? 'bg-emerald-50 text-emerald-500' : item.status === 'error' ? 'bg-red-50 text-red-500' : 'bg-slate-50 text-slate-400']">
                                    <i :class="item.status === 'success' ? 'fa-solid fa-check' : item.status === 'error' ? 'fa-solid fa-xmark' : 'fa-regular fa-file'"></i>
                                </div>
                                <div class="min-w-0 flex-1">
                                    <div class="mb-1.5 flex items-baseline justify-between gap-3">
                                        <span class="truncate text-[13px] font-medium text-slate-700">{{ item.relativePath || item.file.name }}</span>
                                        <span :class="['flex-none text-[11px] font-medium',
                                                       item.status === 'success' ? 'text-emerald-600' : item.status === 'error' ? 'text-red-500' : 'text-slate-400']">{{ item.statusText }}</span>
                                    </div>
                                    <div class="h-1.5 w-full overflow-hidden rounded-full bg-slate-100">
                                        <div :class="['h-full rounded-full transition-all duration-300',
                                                      item.status === 'error' ? 'bg-red-400' : item.status === 'success' ? 'bg-emerald-500' : 'bg-indigo-500']"
                                             :style="{ width: item.progress + '%' }"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div>
                        <div class="mb-3 flex items-center justify-between">
                            <h2 class="text-sm font-semibold text-slate-800">最近上传</h2>
                            <div class="flex gap-2">
                                <button @click="fetchUploadHistory" class="flex h-8 items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 text-[12px] font-medium text-slate-600 transition hover:bg-slate-50">
                                    <i class="fa-solid fa-rotate-right text-[10px]"></i>刷新
                                </button>
                                <button v-if="uploadHistory.length" @click="clearUploadHistory" class="flex h-8 items-center gap-1.5 rounded-lg border border-red-100 bg-red-50 px-3 text-[12px] font-medium text-red-500 transition hover:bg-red-100">
                                    <i class="fa-regular fa-trash-can text-[10px]"></i>清空
                                </button>
                            </div>
                        </div>

                        <div v-if="uploadHistory.length === 0" class="rounded-2xl border border-slate-100 bg-white py-14 text-center shadow-soft">
                            <i class="fa-regular fa-clock mb-3 text-3xl text-slate-200"></i>
                            <p class="text-sm text-slate-400">暂无上传记录</p>
                        </div>

                        <div v-else class="overflow-hidden rounded-2xl border border-slate-100 bg-white shadow-soft">
                            <table class="w-full text-left text-sm">
                                <thead class="border-b border-slate-100 bg-slate-50/70 text-[11px] uppercase tracking-wide text-slate-400">
                                    <tr>
                                        <th class="px-4 py-3 font-medium sm:px-5">文件名</th>
                                        <th class="hidden w-28 px-5 py-3 font-medium sm:table-cell">大小</th>
                                        <th class="w-20 px-4 py-3 text-right font-medium sm:w-44 sm:px-5">时间</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-slate-50">
                                    <tr v-for="(log, idx) in uploadHistory" :key="idx" class="transition hover:bg-slate-50/60">
                                        <td class="max-w-0 truncate px-4 py-3.5 font-medium text-slate-700 sm:px-5">{{ log.name }}</td>
                                        <td class="hidden px-5 py-3.5 text-xs tabular-nums text-slate-500 sm:table-cell">{{ formatSize(log.size) }}</td>
                                        <td class="px-4 py-3.5 text-right text-xs text-slate-400 sm:px-5">{{ formatDate(log.date) }}</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <div v-else-if="currentView === 'files'" class="mx-auto max-w-6xl space-y-5" @click.stop>
                    <div class="sticky top-0 z-10 flex flex-col gap-2.5 rounded-2xl border border-slate-200/70 bg-white/85 p-2.5 shadow-soft backdrop-blur-xl sm:flex-row sm:items-center sm:gap-3">
                        <div class="scroll-thin flex min-w-0 flex-1 items-center gap-0.5 overflow-x-auto text-[13px]">
                            <button @click="navigateTo('')" class="flex flex-none items-center gap-2 rounded-lg px-2.5 py-1.5 font-semibold text-slate-800 transition hover:bg-slate-100">
                                <i class="fa-solid fa-house text-[11px] text-indigo-500"></i>根目录
                            </button>
                            <template v-for="(part, index) in pathParts" :key="index">
                                <i class="fa-solid fa-chevron-right flex-none px-0.5 text-[9px] text-slate-300"></i>
                                <button @click="navigateTo(part.fullPath)" class="flex-none whitespace-nowrap rounded-lg px-2.5 py-1.5 font-medium text-slate-600 transition hover:bg-slate-100">{{ part.name }}</button>
                            </template>
                        </div>

                        <div class="flex items-center gap-2">
                            <template v-if="!isSelectionMode">
                                <div class="relative flex-1 sm:flex-none">
                                    <i class="fa-solid fa-magnifying-glass pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[11px] text-slate-400"></i>
                                    <input v-model="searchQuery" type="text" placeholder="搜索"
                                           class="h-9 w-full rounded-xl border border-slate-200 bg-slate-50 pl-8 pr-3 text-[13px] outline-none transition-all placeholder:text-slate-400 focus:border-indigo-300 focus:bg-white focus:ring-4 focus:ring-indigo-500/10 sm:w-28 sm:focus:w-44">
                                </div>
                                <div class="flex rounded-xl bg-slate-100 p-0.5">
                                    <button @click="viewMode = 'list'" :class="['flex h-8 w-8 items-center justify-center rounded-[9px] text-[11px] transition', viewMode === 'list' ? 'bg-white text-indigo-600 shadow-soft' : 'text-slate-400 hover:text-slate-600']">
                                        <i class="fa-solid fa-list"></i>
                                    </button>
                                    <button @click="viewMode = 'grid'" :class="['flex h-8 w-8 items-center justify-center rounded-[9px] text-[11px] transition', viewMode === 'grid' ? 'bg-white text-indigo-600 shadow-soft' : 'text-slate-400 hover:text-slate-600']">
                                        <i class="fa-solid fa-table-cells-large"></i>
                                    </button>
                                </div>
                                <button @click="createFolderModal.show = true"
                                        class="flex h-9 items-center gap-2 rounded-xl bg-slate-900 px-3.5 text-[13px] font-medium text-white transition hover:bg-slate-800 active:scale-95">
                                    <i class="fa-solid fa-folder-plus text-[11px]"></i><span class="hidden sm:inline">新建</span>
                                </button>
                            </template>
                            <template v-else>
                                <button @click="selectAll" class="h-9 rounded-xl border border-slate-200 bg-white px-3 text-[13px] font-medium text-slate-600 transition hover:bg-slate-50">全选</button>
                                <button @click="invertSelection" class="h-9 rounded-xl border border-slate-200 bg-white px-3 text-[13px] font-medium text-slate-600 transition hover:bg-slate-50">反选</button>
                            </template>
                            <button @click="toggleSelectionMode" :title="isSelectionMode ? '退出多选' : '进入多选'"
                                    :class="['flex h-9 w-9 items-center justify-center rounded-xl text-[13px] transition',
                                             isSelectionMode ? 'bg-indigo-500 text-white shadow-md shadow-indigo-500/30' : 'border border-slate-200 bg-white text-slate-500 hover:text-indigo-600']">
                                <i class="fa-solid fa-check-double"></i>
                            </button>
                        </div>
                    </div>

                    <div v-if="sortedFiles.length === 0" class="rounded-4xl border border-slate-100 bg-white py-20 text-center shadow-soft">
                        <div class="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-slate-50 text-2xl text-slate-300">
                            <i :class="searchQuery ? 'fa-solid fa-magnifying-glass' : 'fa-regular fa-folder-open'"></i>
                        </div>
                        <p class="text-[15px] font-medium text-slate-700">{{ searchQuery ? '没有匹配的文件' : '这个文件夹是空的' }}</p>
                        <p class="mt-1 text-sm text-slate-400">{{ searchQuery ? '换个关键词试试，或清空搜索框' : '上传文件后它们会出现在这里' }}</p>
                        <button v-if="searchQuery" @click="searchQuery = ''" class="mt-5 h-9 rounded-xl border border-slate-200 bg-white px-4 text-[13px] font-medium text-slate-600 transition hover:bg-slate-50">清空搜索</button>
                        <button v-else @click="pickFiles" class="mt-5 h-9 rounded-xl bg-slate-900 px-4 text-[13px] font-medium text-white transition hover:bg-slate-800">上传文件</button>
                    </div>

                    <div v-else-if="viewMode === 'list'" class="overflow-hidden rounded-2xl border border-slate-100 bg-white shadow-soft">
                        <table class="w-full text-left">
                            <thead class="border-b border-slate-100 bg-slate-50/70 text-[11px] uppercase tracking-wide text-slate-400">
                                <tr>
                                    <th v-if="isSelectionMode" class="w-12 py-3 pl-4 sm:pl-5">
                                        <input type="checkbox" class="cbx" :checked="isAllSelected" @change="toggleSelectAll">
                                    </th>
                                    <th class="px-4 py-3 font-medium sm:px-5">名称</th>
                                    <th class="hidden w-28 px-5 py-3 font-medium sm:table-cell">大小</th>
                                    <th class="w-20 px-4 py-3 text-right font-medium sm:w-40 sm:px-5">修改时间</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-slate-50 text-sm">
                                <tr v-for="file in sortedFiles" :key="file.key"
                                    :class="['group cursor-default select-none transition', selectedFiles.includes(file.key) ? 'bg-indigo-50/70' : 'hover:bg-slate-50/70']"
                                    @contextmenu.prevent.stop="showContextMenu($event, file)"
                                    @click="handleRowClick(file)">
                                    <td v-if="isSelectionMode" class="w-12 py-3.5 pl-4 sm:pl-5" @click.stop>
                                        <input type="checkbox" class="cbx" :value="file.key" v-model="selectedFiles">
                                    </td>
                                    <td class="max-w-0 px-4 py-3.5 sm:px-5">
                                        <div class="flex items-center gap-3.5">
                                            <div :class="['flex h-9 w-9 flex-none items-center justify-center rounded-xl text-[15px] transition-transform group-hover:scale-105',
                                                          file.isFolder ? 'bg-amber-50 text-amber-500' : fileTint(file)]">
                                                <i :class="getFileIcon(file)"></i>
                                            </div>
                                            <span class="truncate font-medium text-slate-700 transition-colors group-hover:text-indigo-600">{{ getDisplayName(file.key) }}</span>
                                        </div>
                                    </td>
                                    <td class="hidden px-5 py-3.5 text-xs tabular-nums text-slate-400 sm:table-cell">{{ file.isFolder ? '—' : formatSize(file.size) }}</td>
                                    <td class="px-4 py-3.5 text-right text-xs text-slate-400 sm:px-5">{{ file.uploaded ? formatDate(file.uploaded) : '—' }}</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>

                    <div v-else class="grid grid-cols-2 gap-3.5 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6">
                        <div v-for="file in sortedFiles" :key="file.key"
                             :class="['card-hover group relative flex cursor-pointer flex-col items-center gap-3 rounded-2xl border bg-white p-4',
                                      selectedFiles.includes(file.key) ? 'border-indigo-300 bg-indigo-50/50 ring-2 ring-indigo-500/20' : 'border-slate-100 shadow-soft hover:border-slate-200']"
                             @click="handleRowClick(file)"
                             @contextmenu.prevent.stop="showContextMenu($event, file)">
                            <div v-if="isSelectionMode" class="absolute right-2.5 top-2.5 z-10" @click.stop>
                                <input type="checkbox" class="cbx" :value="file.key" v-model="selectedFiles">
                            </div>
                            <div :class="['flex h-14 w-14 items-center justify-center rounded-2xl text-[26px] transition-transform duration-300 group-hover:scale-110',
                                          file.isFolder ? 'bg-amber-50 text-amber-500' : fileTint(file)]">
                                <i :class="getFileIcon(file)"></i>
                            </div>
                            <div class="w-full text-center">
                                <div class="truncate px-1 text-[12.5px] font-medium text-slate-700 transition-colors group-hover:text-indigo-600">{{ getDisplayName(file.key) }}</div>
                                <div class="mt-0.5 text-[10.5px] tabular-nums text-slate-400">{{ file.isFolder ? '文件夹' : formatSize(file.size) }}</div>
                            </div>
                        </div>
                    </div>
                </div>

                <div v-else-if="currentView === 'shares'" class="mx-auto max-w-6xl space-y-5" @click.stop>
                    <div class="flex flex-wrap items-end justify-between gap-3">
                        <div>
                            <h1 class="text-xl font-semibold tracking-tight text-slate-900">分享管理</h1>
                            <p class="mt-1 text-sm text-slate-500">共 {{ shares.length }} 个分享链接</p>
                        </div>
                        <div class="flex items-center gap-2">
                            <template v-if="isShareSelectionMode">
                                <button @click="selectAllShares" class="h-9 rounded-xl border border-slate-200 bg-white px-3 text-[13px] font-medium text-slate-600 transition hover:bg-slate-50">全选</button>
                                <button @click="invertShareSelection" class="h-9 rounded-xl border border-slate-200 bg-white px-3 text-[13px] font-medium text-slate-600 transition hover:bg-slate-50">反选</button>
                            </template>
                            <button @click="fetchShares" title="刷新" class="flex h-9 w-9 items-center justify-center rounded-xl border border-slate-200 bg-white text-slate-500 transition hover:text-indigo-600">
                                <i class="fa-solid fa-rotate-right text-xs"></i>
                            </button>
                            <button @click="toggleShareSelectionMode"
                                    :class="['flex h-9 items-center gap-2 rounded-xl px-3.5 text-[13px] font-medium transition',
                                             isShareSelectionMode ? 'bg-indigo-500 text-white shadow-md shadow-indigo-500/30' : 'border border-slate-200 bg-white text-slate-600 hover:bg-slate-50']">
                                <i class="fa-solid fa-check-double text-[11px]"></i>多选
                            </button>
                        </div>
                    </div>

                    <div v-if="shares.length === 0" class="rounded-4xl border border-slate-100 bg-white py-20 text-center shadow-soft">
                        <div class="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-slate-50 text-2xl text-slate-300">
                            <i class="fa-solid fa-share-nodes"></i>
                        </div>
                        <p class="text-[15px] font-medium text-slate-700">还没有创建分享</p>
                        <p class="mt-1 text-sm text-slate-400">在「全部文件」中右键任意文件即可生成分享链接</p>
                        <button @click="switchView('files')" class="mt-5 h-9 rounded-xl bg-slate-900 px-4 text-[13px] font-medium text-white transition hover:bg-slate-800">去选择文件</button>
                    </div>

                    <div v-else class="overflow-hidden rounded-2xl border border-slate-100 bg-white shadow-soft">
                        <table class="w-full text-left text-sm">
                            <thead class="border-b border-slate-100 bg-slate-50/70 text-[11px] uppercase tracking-wide text-slate-400">
                                <tr>
                                    <th v-if="isShareSelectionMode" class="w-12 py-3 pl-4 sm:pl-5">
                                        <input type="checkbox" class="cbx" :checked="isAllSharesSelected" @change="e => selectedShares = e.target.checked ? shares.map(s => s.token) : []">
                                    </th>
                                    <th class="px-4 py-3 font-medium sm:px-5">文件</th>
                                    <th class="hidden w-32 px-5 py-3 font-medium md:table-cell">Token</th>
                                    <th class="hidden w-24 px-5 py-3 text-center font-medium sm:table-cell">访问</th>
                                    <th class="w-24 px-4 py-3 text-right font-medium sm:w-36 sm:px-5">状态</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-slate-50">
                                <tr v-for="item in shares" :key="item.token"
                                    :class="['transition', selectedShares.includes(item.token) ? 'bg-indigo-50/70' : 'hover:bg-slate-50/70', isShareSelectionMode ? 'cursor-pointer' : '']"
                                    @click="isShareSelectionMode ? toggleShareSelection(item.token) : null"
                                    @contextmenu.prevent.stop="showContextMenu($event, item, 'share')">
                                    <td v-if="isShareSelectionMode" class="w-12 py-3.5 pl-4 sm:pl-5" @click.stop>
                                        <input type="checkbox" class="cbx" :value="item.token" v-model="selectedShares">
                                    </td>
                                    <td class="max-w-0 px-4 py-3.5 sm:px-5">
                                        <div class="truncate font-medium text-slate-700" :title="item.path">{{ item.path }}</div>
                                        <div class="mt-1 flex items-center gap-1.5 md:hidden">
                                            <span class="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">{{ item.token }}</span>
                                            <span class="text-[10px] text-slate-400">{{ item.views }} 次访问</span>
                                        </div>
                                    </td>
                                    <td class="hidden px-5 py-3.5 md:table-cell">
                                        <span class="select-all rounded-md bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-slate-500">{{ item.token }}</span>
                                    </td>
                                    <td class="hidden px-5 py-3.5 text-center sm:table-cell">
                                        <span class="text-[13px] font-semibold tabular-nums text-slate-700">{{ item.views }}</span>
                                        <span v-if="item.maxViews" class="text-[11px] text-slate-400"> / {{ item.maxViews }}</span>
                                    </td>
                                    <td class="px-4 py-3.5 sm:px-5">
                                        <div class="flex flex-wrap items-center justify-end gap-1.5">
                                            <span v-if="item.password" class="inline-flex items-center gap-1 rounded-md border border-amber-200 bg-amber-50 px-1.5 py-0.5 text-[10px] font-medium text-amber-600">
                                                <i class="fa-solid fa-lock text-[8px]"></i>加密
                                            </span>
                                            <span v-if="item.expireTime" :class="['inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] font-medium',
                                                                                          isExpired(item) ? 'border-red-100 bg-red-50 text-red-500' : 'border-emerald-100 bg-emerald-50 text-emerald-600']">
                                                {{ isExpired(item) ? '已过期' : '有效' }}
                                            </span>
                                            <span v-if="!item.password && !item.expireTime" class="text-[10px] text-slate-300">—</span>
                                        </div>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div v-else-if="currentView === 'trash'" class="mx-auto max-w-6xl space-y-5" @click.stop>
                    <div class="flex flex-wrap items-end justify-between gap-3">
                        <div>
                            <h1 class="text-xl font-semibold tracking-tight text-slate-900">回收站</h1>
                            <p class="mt-1 text-sm text-slate-500">
                                <template v-if="trashFiles.length">共 {{ trashFiles.length }} 项，删除后仍可还原</template>
                                <template v-else>删除的文件会暂存在这里</template>
                            </p>
                        </div>
                        <div v-if="trashFiles.length" class="flex items-center gap-2">
                            <button @click="selectedTrash = selectedTrash.length === trashFiles.length ? [] : trashFiles.map(t => t.key)"
                                    class="h-9 rounded-xl border border-slate-200 bg-white px-3 text-[13px] font-medium text-slate-600 transition hover:bg-slate-50">
                                {{ selectedTrash.length === trashFiles.length ? '取消全选' : '全选' }}
                            </button>
                            <button @click="fetchTrash" title="刷新" class="flex h-9 w-9 items-center justify-center rounded-xl border border-slate-200 bg-white text-slate-500 transition hover:text-indigo-600">
                                <i class="fa-solid fa-rotate-right text-xs"></i>
                            </button>
                        </div>
                    </div>

                    <div v-if="trashFiles.length === 0" class="rounded-4xl border border-slate-100 bg-white py-20 text-center shadow-soft">
                        <div class="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-slate-50 text-2xl text-slate-300">
                            <i class="fa-regular fa-trash-can"></i>
                        </div>
                        <p class="text-[15px] font-medium text-slate-700">回收站是空的</p>
                        <p class="mt-1 text-sm text-slate-400">被删除的文件会先移到这里，可随时还原</p>
                    </div>

                    <div v-else class="overflow-hidden rounded-2xl border border-slate-100 bg-white shadow-soft">
                        <table class="w-full text-left text-sm">
                            <thead class="border-b border-slate-100 bg-slate-50/70 text-[11px] uppercase tracking-wide text-slate-400">
                                <tr>
                                    <th class="w-12 py-3 pl-4 sm:pl-5">
                                        <input type="checkbox" class="cbx" :checked="trashFiles.length > 0 && selectedTrash.length === trashFiles.length"
                                               @change="e => selectedTrash = e.target.checked ? trashFiles.map(t => t.key) : []">
                                    </th>
                                    <th class="px-4 py-3 font-medium sm:px-5">原路径</th>
                                    <th class="hidden w-28 px-5 py-3 font-medium sm:table-cell">大小</th>
                                    <th class="w-20 px-4 py-3 text-right font-medium sm:w-44 sm:px-5">删除时间</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-slate-50">
                                <tr v-for="item in trashFiles" :key="item.key"
                                    :class="['transition', selectedTrash.includes(item.key) ? 'bg-indigo-50/70' : 'hover:bg-slate-50/70']">
                                    <td class="w-12 py-3.5 pl-4 sm:pl-5">
                                        <input type="checkbox" class="cbx" :value="item.key" v-model="selectedTrash">
                                    </td>
                                    <td class="max-w-0 px-4 py-3.5 sm:px-5">
                                        <div class="flex items-center gap-3">
                                            <div class="flex h-8 w-8 flex-none items-center justify-center rounded-lg bg-slate-50 text-xs text-slate-400">
                                                <i :class="item.originalPath.endsWith('/') ? 'fa-regular fa-folder' : 'fa-regular fa-file'"></i>
                                            </div>
                                            <span class="truncate font-medium text-slate-600">{{ item.originalPath }}</span>
                                        </div>
                                    </td>
                                    <td class="hidden px-5 py-3.5 text-xs tabular-nums text-slate-400 sm:table-cell">{{ formatSize(item.size) }}</td>
                                    <td class="px-4 py-3.5 text-right text-xs text-slate-400 sm:px-5">{{ formatDate(item.deletedAt) }}</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div v-else-if="currentView === 'settings'" class="mx-auto max-w-2xl space-y-5" @click.stop>
                    <div>
                        <h1 class="text-xl font-semibold tracking-tight text-slate-900">系统设置</h1>
                        <p class="mt-1 text-sm text-slate-500">账户安全与存储概览</p>
                    </div>

                    <div class="grid grid-cols-2 gap-4">
                        <div class="rounded-2xl border border-indigo-100 bg-gradient-to-br from-indigo-50 to-white p-5">
                            <div class="mb-2 flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-100 text-xs text-indigo-600"><i class="fa-solid fa-database"></i></div>
                            <div class="text-[11px] font-medium uppercase tracking-wide text-indigo-400">已用空间</div>
                            <div class="mt-0.5 text-[22px] font-semibold tabular-nums text-slate-800">{{ stats.sizeStr || '—' }}</div>
                        </div>
                        <div class="rounded-2xl border border-violet-100 bg-gradient-to-br from-violet-50 to-white p-5">
                            <div class="mb-2 flex h-8 w-8 items-center justify-center rounded-lg bg-violet-100 text-xs text-violet-600"><i class="fa-solid fa-layer-group"></i></div>
                            <div class="text-[11px] font-medium uppercase tracking-wide text-violet-400">文件数量</div>
                            <div class="mt-0.5 text-[22px] font-semibold tabular-nums text-slate-800">{{ stats.count ?? '—' }}</div>
                        </div>
                    </div>

                    <div class="rounded-2xl border border-slate-100 bg-white p-6 shadow-soft">
                        <div class="mb-5 flex items-start gap-3">
                            <div class="flex h-9 w-9 flex-none items-center justify-center rounded-xl bg-amber-50 text-sm text-amber-500"><i class="fa-solid fa-key"></i></div>
                            <div>
                                <h2 class="text-sm font-semibold text-slate-800">修改管理员密码</h2>
                                <p class="mt-0.5 text-[13px] text-slate-500">密码至少 6 位。修改后所有设备上的登录状态会被注销。</p>
                            </div>
                        </div>
                        <div class="flex flex-col gap-3 sm:flex-row">
                            <input v-model="newPassword" type="password" autocomplete="new-password" placeholder="输入新密码"
                                   class="h-11 flex-1 rounded-xl border border-slate-200 bg-slate-50 px-4 text-sm outline-none transition placeholder:text-slate-400 focus:border-indigo-400 focus:bg-white focus:ring-4 focus:ring-indigo-500/10">
                            <button @click="updatePassword" :disabled="newPassword.length < 6"
                                    class="h-11 flex-none rounded-xl bg-slate-900 px-6 text-sm font-medium text-white transition hover:bg-slate-800 active:scale-95 disabled:cursor-not-allowed disabled:opacity-40">
                                保存修改
                            </button>
                        </div>
                    </div>

                    <div class="rounded-2xl border border-slate-100 bg-white p-6 shadow-soft">
                        <div class="flex items-start gap-3">
                            <div class="flex h-9 w-9 flex-none items-center justify-center rounded-xl bg-slate-100 text-sm text-slate-500"><i class="fa-solid fa-circle-info"></i></div>
                            <div class="min-w-0 flex-1">
                                <h2 class="text-sm font-semibold text-slate-800">关于本系统</h2>
                                <div class="mt-2 space-y-1.5 text-[13px] text-slate-500">
                                    <div class="flex justify-between gap-4"><span>应用</span><span class="font-medium text-slate-700">Cloud Space · R2 文件管理</span></div>
                                    <div class="flex justify-between gap-4"><span>版本</span><span class="font-mono text-slate-700">v3.2.0</span></div>
                                    <div class="flex justify-between gap-4"><span>存储后端</span><span class="font-medium text-slate-700">Cloudflare R2</span></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

            </div>

            <transition name="rise">
                <div v-if="selectedFiles.length > 0 && currentView === 'files'" class="pointer-events-none absolute bottom-7 left-0 right-0 z-20 flex justify-center px-4">
                    <div class="pointer-events-auto flex items-center gap-1.5 rounded-2xl border border-white/10 bg-slate-900/95 p-1.5 pl-4 shadow-pop backdrop-blur-md">
                        <span class="mr-1 text-[13px] font-medium text-white">已选 {{ selectedFiles.length }} 项</span>
                        <span class="mx-1 h-5 w-px bg-white/15"></span>
                        <button @click="openMoveModal" class="flex items-center gap-2 rounded-xl px-3 py-2 text-[13px] font-medium text-slate-300 transition hover:bg-white/10 hover:text-white">
                            <i class="fa-solid fa-arrow-right-to-bracket text-[11px]"></i>移动
                        </button>
                        <button @click="batchDelete" class="flex items-center gap-2 rounded-xl px-3 py-2 text-[13px] font-medium text-red-300 transition hover:bg-red-500/15 hover:text-red-200">
                            <i class="fa-regular fa-trash-can text-[11px]"></i>删除
                        </button>
                        <button @click="selectedFiles = []" class="ml-1 flex h-8 w-8 items-center justify-center rounded-xl text-slate-400 transition hover:bg-white/10 hover:text-white">
                            <i class="fa-solid fa-xmark text-xs"></i>
                        </button>
                    </div>
                </div>
            </transition>

            <transition name="rise">
                <div v-if="selectedShares.length > 0 && currentView === 'shares'" class="pointer-events-none absolute bottom-7 left-0 right-0 z-20 flex justify-center px-4">
                    <div class="pointer-events-auto flex items-center gap-1.5 rounded-2xl border border-white/10 bg-slate-900/95 p-1.5 pl-4 shadow-pop backdrop-blur-md">
                        <span class="mr-1 text-[13px] font-medium text-white">选中 {{ selectedShares.length }} 项</span>
                        <span class="mx-1 h-5 w-px bg-white/15"></span>
                        <button @click="batchCopyLinks" class="flex items-center gap-2 rounded-xl px-3 py-2 text-[13px] font-medium text-indigo-300 transition hover:bg-indigo-500/15 hover:text-indigo-200">
                            <i class="fa-regular fa-copy text-[11px]"></i>复制链接
                        </button>
                        <button @click="batchDeleteShares" class="flex items-center gap-2 rounded-xl px-3 py-2 text-[13px] font-medium text-red-300 transition hover:bg-red-500/15 hover:text-red-200">
                            <i class="fa-solid fa-link-slash text-[11px]"></i>撤销
                        </button>
                        <button @click="selectedShares = []" class="ml-1 flex h-8 w-8 items-center justify-center rounded-xl text-slate-400 transition hover:bg-white/10 hover:text-white">
                            <i class="fa-solid fa-xmark text-xs"></i>
                        </button>
                    </div>
                </div>
            </transition>
            <transition name="rise">
                <div v-if="selectedTrash.length > 0 && currentView === 'trash'" class="pointer-events-none absolute bottom-7 left-0 right-0 z-20 flex justify-center px-4">
                    <div class="pointer-events-auto flex items-center gap-1.5 rounded-2xl border border-white/10 bg-slate-900/95 p-1.5 pl-4 shadow-pop backdrop-blur-md">
                        <span class="mr-1 text-[13px] font-medium text-white">选中 {{ selectedTrash.length }} 项</span>
                        <span class="mx-1 h-5 w-px bg-white/15"></span>
                        <button @click="restoreTrash" class="flex items-center gap-2 rounded-xl px-3 py-2 text-[13px] font-medium text-emerald-300 transition hover:bg-emerald-500/15 hover:text-emerald-200">
                            <i class="fa-solid fa-rotate-left text-[11px]"></i>还原
                        </button>
                        <button @click="deleteTrashForever" class="flex items-center gap-2 rounded-xl px-3 py-2 text-[13px] font-medium text-red-300 transition hover:bg-red-500/15 hover:text-red-200">
                            <i class="fa-regular fa-trash-can text-[11px]"></i>彻底删除
                        </button>
                        <button @click="selectedTrash = []" class="ml-1 flex h-8 w-8 items-center justify-center rounded-xl text-slate-400 transition hover:bg-white/10 hover:text-white">
                            <i class="fa-solid fa-xmark text-xs"></i>
                        </button>
                    </div>
                </div>
            </transition>
        </main>

        <transition name="pop">
            <div v-if="lightbox.show" class="fixed inset-0 z-[3000] flex flex-col items-center justify-center bg-slate-950/95 backdrop-blur-md" @click="lightbox.show = false">
                <button class="absolute right-5 top-5 flex h-10 w-10 items-center justify-center rounded-full bg-white/10 text-white transition hover:bg-white/20">
                    <i class="fa-solid fa-xmark"></i>
                </button>
                <img v-if="lightbox.type === 'image'" :src="lightbox.url" class="max-h-[84vh] max-w-[92%] rounded-2xl object-contain shadow-2xl" @click.stop>
                <video v-if="lightbox.type === 'video'" :src="lightbox.url" controls autoplay class="max-h-[84vh] max-w-[92%] rounded-2xl shadow-2xl" @click.stop></video>
                <div class="mt-5 rounded-full bg-white/10 px-4 py-2 text-[13px] font-medium text-white/85 backdrop-blur">{{ lightbox.name }}</div>
            </div>
        </transition>

        <transition name="pop">
            <div v-if="editor.show" class="fixed inset-0 z-[2500] flex items-center justify-center bg-slate-900/45 p-4 backdrop-blur-sm" @click.self="editor.show = false">
                <div class="flex h-[86vh] w-full max-w-4xl flex-col overflow-hidden rounded-3xl bg-white shadow-pop">
                    <div class="flex items-center justify-between gap-3 border-b border-slate-100 bg-slate-50/60 px-5 py-3.5">
                        <div class="flex min-w-0 items-center gap-2.5">
                            <div class="flex h-8 w-8 flex-none items-center justify-center rounded-lg bg-indigo-50 text-xs text-indigo-600"><i class="fa-solid fa-code"></i></div>
                            <span class="truncate text-sm font-semibold text-slate-800">{{ editor.filename }}</span>
                        </div>
                        <div class="flex flex-none items-center gap-2">
                            <button v-if="isMarkdown" @click="editor.previewMode = !editor.previewMode"
                                    class="flex h-9 items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 text-[13px] font-medium text-slate-600 transition hover:bg-slate-50">
                                <i :class="editor.previewMode ? 'fa-solid fa-pen' : 'fa-regular fa-eye'" class="text-[11px]"></i>
                                {{ editor.previewMode ? '编辑' : '预览' }}
                            </button>
                            <button @click="editor.show = false" class="h-9 rounded-xl px-3 text-[13px] font-medium text-slate-500 transition hover:bg-slate-100">关闭</button>
                            <button @click="saveTextContent" :disabled="editor.saving"
                                    class="flex h-9 items-center gap-2 rounded-xl bg-slate-900 px-4 text-[13px] font-medium text-white transition hover:bg-slate-800 active:scale-95 disabled:opacity-60">
                                <i :class="editor.saving ? 'fa-solid fa-circle-notch fa-spin' : 'fa-regular fa-floppy-disk'" class="text-[11px]"></i>保存
                            </button>
                        </div>
                    </div>
                    <div class="relative flex-1 overflow-hidden">
                        <textarea v-show="!editor.previewMode" v-model="editor.content" spellcheck="false"
                                  class="scroll-thin h-full w-full resize-none p-6 font-mono text-[13px] leading-relaxed text-slate-700 outline-none"
                                  @keydown.ctrl.s.prevent="saveTextContent" @keydown.meta.s.prevent="saveTextContent"></textarea>
                        <div v-show="editor.previewMode" class="scroll-thin prose-custom h-full w-full overflow-y-auto p-6 text-[14px] text-slate-700" v-html="compiledMarkdown"></div>
                    </div>
                </div>
            </div>
        </transition>

        <div v-if="contextMenu.visible" :style="{ top: contextMenu.y + 'px', left: contextMenu.x + 'px' }" class="ctx" @click.stop @contextmenu.prevent>
            <template v-if="contextMenu.type === 'share'">
                <div class="px-3 pb-1.5 pt-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">分享操作</div>
                <div class="ctx-item" @click="handleMenuAction('openShare')"><i class="fa-solid fa-arrow-up-right-from-square text-slate-400"></i>打开链接</div>
                <div class="ctx-item" @click="handleMenuAction('copyShare')"><i class="fa-regular fa-copy text-indigo-500"></i>复制链接</div>
                <div class="ctx-sep"></div>
                <div class="ctx-item is-danger" @click="handleMenuAction('deleteShare')"><i class="fa-solid fa-link-slash"></i>撤销分享</div>
            </template>
            <template v-else-if="contextMenu.type === 'batch-share'">
                <div class="px-3 pb-1.5 pt-1 text-[10px] font-semibold uppercase tracking-wider text-indigo-500">已选 {{ selectedShares.length }} 项</div>
                <div class="ctx-item" @click="batchCopyLinks"><i class="fa-regular fa-copy text-indigo-500"></i>批量复制链接</div>
                <div class="ctx-item is-danger" @click="batchDeleteShares"><i class="fa-solid fa-link-slash"></i>批量撤销</div>
                <div class="ctx-sep"></div>
                <div class="ctx-item" @click="selectedShares = []; contextMenu.visible = false"><i class="fa-solid fa-xmark text-slate-400"></i>取消选择</div>
            </template>
            <template v-else-if="contextMenu.type === 'batch'">
                <div class="px-3 pb-1.5 pt-1 text-[10px] font-semibold uppercase tracking-wider text-indigo-500">已选 {{ selectedFiles.length }} 项</div>
                <div class="ctx-item" @click="openMoveModal(); contextMenu.visible = false"><i class="fa-solid fa-arrow-right-to-bracket text-slate-400"></i>批量移动</div>
                <div class="ctx-item is-danger" @click="batchDelete"><i class="fa-regular fa-trash-can"></i>批量删除</div>
                <div class="ctx-sep"></div>
                <div class="ctx-item" @click="selectedFiles = []; contextMenu.visible = false"><i class="fa-solid fa-xmark text-slate-400"></i>取消选择</div>
            </template>
            <template v-else>
                <div class="truncate px-3 pb-1.5 pt-1 text-[10px] font-semibold text-slate-400" :title="getDisplayName(contextMenu.file.key)">{{ getDisplayName(contextMenu.file.key) }}</div>
                <div v-if="!contextMenu.file.isFolder" class="ctx-item" @click="handleMenuAction('preview')"><i class="fa-regular fa-eye text-indigo-500"></i>预览</div>
                <div v-if="isTextFile(contextMenu.file.key)" class="ctx-item" @click="handleMenuAction('edit')"><i class="fa-solid fa-pen-to-square text-amber-500"></i>编辑文本</div>
                <div v-if="!contextMenu.file.isFolder" class="ctx-item" @click="handleMenuAction('download')"><i class="fa-solid fa-download text-slate-400"></i>下载</div>
                <div class="ctx-item" @click="handleMenuAction('rename')"><i class="fa-solid fa-i-cursor text-slate-400"></i>重命名</div>
                <div class="ctx-item" @click="handleMenuAction('move')"><i class="fa-solid fa-arrow-right-to-bracket text-slate-400"></i>移动到…</div>
                <div v-if="!contextMenu.file.isFolder" class="ctx-item" @click="handleMenuAction('share')"><i class="fa-solid fa-share-nodes text-emerald-500"></i>创建分享</div>
                <div class="ctx-sep"></div>
                <div class="ctx-item is-danger" @click="handleMenuAction('delete')"><i class="fa-regular fa-trash-can"></i>删除</div>
            </template>
        </div>

        <transition name="pop">
            <div v-if="shareConfigModal.show" class="fixed inset-0 z-[2000] flex items-center justify-center bg-slate-900/45 p-4 backdrop-blur-sm" @click.self="shareConfigModal.show = false">
                <div class="w-full max-w-md rounded-3xl bg-white p-6 shadow-pop">
                    <div class="mb-5 flex items-center gap-3">
                        <div class="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-50 text-emerald-500"><i class="fa-solid fa-share-nodes"></i></div>
                        <div>
                            <h3 class="text-[15px] font-semibold text-slate-900">创建分享链接</h3>
                            <p class="text-[12px] text-slate-500">可设置访问密码、有效期与次数上限</p>
                        </div>
                    </div>
                    <div class="mb-5 truncate rounded-xl bg-slate-50 px-3.5 py-2.5 font-mono text-[12px] text-slate-500">{{ shareConfigModal.path }}</div>
                    <div class="space-y-4">
                        <div>
                            <label class="mb-1.5 block text-xs font-medium text-slate-500">访问密码（可选）</label>
                            <input v-model="shareConfigModal.password" type="text" placeholder="留空表示无需密码"
                                   class="h-11 w-full rounded-xl border border-slate-200 bg-slate-50 px-4 text-sm outline-none transition placeholder:text-slate-400 focus:border-indigo-400 focus:bg-white focus:ring-4 focus:ring-indigo-500/10">
                        </div>
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <label class="mb-1.5 block text-xs font-medium text-slate-500">有效期</label>
                                <select v-model="shareConfigModal.expireHours"
                                        class="h-11 w-full rounded-xl border border-slate-200 bg-slate-50 px-3 text-sm outline-none transition focus:border-indigo-400 focus:bg-white">
                                    <option value="">永久有效</option>
                                    <option value="1">1 小时</option>
                                    <option value="24">24 小时</option>
                                    <option value="168">7 天</option>
                                    <option value="720">30 天</option>
                                </select>
                            </div>
                            <div>
                                <label class="mb-1.5 block text-xs font-medium text-slate-500">次数上限</label>
                                <input v-model="shareConfigModal.maxViews" type="number" min="1" placeholder="不限"
                                       class="h-11 w-full rounded-xl border border-slate-200 bg-slate-50 px-4 text-sm outline-none transition placeholder:text-slate-400 focus:border-indigo-400 focus:bg-white focus:ring-4 focus:ring-indigo-500/10">
                            </div>
                        </div>
                    </div>
                    <div class="mt-6 flex justify-end gap-2.5">
                        <button @click="shareConfigModal.show = false" class="h-10 rounded-xl px-4 text-[13px] font-medium text-slate-500 transition hover:bg-slate-100">取消</button>
                        <button @click="confirmCreateShare" class="h-10 rounded-xl bg-emerald-500 px-5 text-[13px] font-medium text-white shadow-md shadow-emerald-500/25 transition hover:bg-emerald-600 active:scale-95">生成链接</button>
                    </div>
                </div>
            </div>
        </transition>

        <transition name="pop">
            <div v-if="createFolderModal.show" class="fixed inset-0 z-[2000] flex items-center justify-center bg-slate-900/45 p-4 backdrop-blur-sm" @click.self="createFolderModal.show = false">
                <div class="w-full max-w-sm rounded-3xl bg-white p-6 shadow-pop">
                    <h3 class="mb-5 text-[15px] font-semibold text-slate-900">新建文件夹</h3>
                    <input v-model="createFolderModal.name" type="text" placeholder="输入文件夹名称" autofocus
                           class="h-11 w-full rounded-xl border border-slate-200 bg-slate-50 px-4 text-sm outline-none transition placeholder:text-slate-400 focus:border-indigo-400 focus:bg-white focus:ring-4 focus:ring-indigo-500/10"
                           @keyup.enter="createFolder">
                    <div class="mt-6 flex justify-end gap-2.5">
                        <button @click="createFolderModal.show = false" class="h-10 rounded-xl px-4 text-[13px] font-medium text-slate-500 transition hover:bg-slate-100">取消</button>
                        <button @click="createFolder" class="h-10 rounded-xl bg-slate-900 px-5 text-[13px] font-medium text-white transition hover:bg-slate-800 active:scale-95">创建</button>
                    </div>
                </div>
            </div>
        </transition>

        <transition name="pop">
            <div v-if="moveModal.show" class="fixed inset-0 z-[2000] flex items-center justify-center bg-slate-900/45 p-4 backdrop-blur-sm" @click.self="moveModal.show = false">
                <div class="flex max-h-[72vh] w-full max-w-md flex-col rounded-3xl bg-white p-6 shadow-pop">
                    <h3 class="mb-1 text-[15px] font-semibold text-slate-900">移动到…</h3>
                    <p class="mb-5 text-[12px] text-slate-500">将 {{ selectedFiles.length }} 个项目移动到目标目录</p>
                    <div class="relative mb-3">
                        <i class="fa-solid fa-folder-tree pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-xs text-slate-400"></i>
                        <input v-model="moveModal.target" type="text" placeholder="目标路径，如 photos/2026/"
                               class="h-11 w-full rounded-xl border border-slate-200 bg-slate-50 pl-10 pr-4 text-sm outline-none transition placeholder:text-slate-400 focus:border-indigo-400 focus:bg-white focus:ring-4 focus:ring-indigo-500/10">
                    </div>
                    <div class="scroll-thin min-h-[120px] flex-1 overflow-y-auto rounded-xl border border-slate-100 bg-slate-50/60 p-2">
                        <div class="px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">选择已有文件夹</div>
                        <div @click="moveModal.target = ''"
                             :class="['flex cursor-pointer items-center gap-2.5 rounded-lg px-2.5 py-2 text-[13px] transition',
                                      moveModal.target === '' ? 'bg-white font-semibold text-indigo-600 shadow-soft' : 'text-slate-600 hover:bg-white/70']">
                            <i class="fa-solid fa-server text-xs text-slate-400"></i>根目录
                        </div>
                        <div v-for="f in moveModal.folderList" :key="f" @click="moveModal.target = f"
                             :class="['flex cursor-pointer items-center gap-2.5 rounded-lg px-2.5 py-2 text-[13px] transition',
                                      moveModal.target === f ? 'bg-white font-semibold text-indigo-600 shadow-soft' : 'text-slate-600 hover:bg-white/70']">
                            <i class="fa-regular fa-folder text-xs text-amber-500"></i><span class="truncate">{{ f }}</span>
                        </div>
                        <div v-if="moveModal.folderList.length === 0" class="px-2.5 py-3 text-[12px] text-slate-400">还没有子文件夹</div>
                    </div>
                    <div class="mt-6 flex justify-end gap-2.5">
                        <button @click="moveModal.show = false" class="h-10 rounded-xl px-4 text-[13px] font-medium text-slate-500 transition hover:bg-slate-100">取消</button>
                        <button @click="confirmMove" class="h-10 rounded-xl bg-indigo-600 px-5 text-[13px] font-medium text-white shadow-md shadow-indigo-500/25 transition hover:bg-indigo-700 active:scale-95">移动</button>
                    </div>
                </div>
            </div>
        </transition>

        <transition name="pop">
            <div v-if="renameModal.show" class="fixed inset-0 z-[2000] flex items-center justify-center bg-slate-900/45 p-4 backdrop-blur-sm" @click.self="renameModal.show = false">
                <div class="w-full max-w-sm rounded-3xl bg-white p-6 shadow-pop">
                    <h3 class="mb-5 text-[15px] font-semibold text-slate-900">重命名</h3>
                    <input v-model="renameModal.newKey" type="text"
                           class="h-11 w-full rounded-xl border border-slate-200 bg-slate-50 px-4 text-sm outline-none transition focus:border-indigo-400 focus:bg-white focus:ring-4 focus:ring-indigo-500/10"
                           @keyup.enter="confirmRename">
                    <div class="mt-6 flex justify-end gap-2.5">
                        <button @click="renameModal.show = false" class="h-10 rounded-xl px-4 text-[13px] font-medium text-slate-500 transition hover:bg-slate-100">取消</button>
                        <button @click="confirmRename" class="h-10 rounded-xl bg-slate-900 px-5 text-[13px] font-medium text-white transition hover:bg-slate-800 active:scale-95">保存</button>
                    </div>
                </div>
            </div>
        </transition>

        <transition name="pop">
            <div v-if="confirmBox.show" class="fixed inset-0 z-[4000] flex items-center justify-center bg-slate-900/45 p-4 backdrop-blur-sm" @click.self="cancelConfirm">
                <div class="w-full max-w-sm rounded-3xl bg-white p-6 text-center shadow-pop">
                    <div :class="['mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl text-xl',
                                  confirmBox.danger ? 'bg-red-50 text-red-500' : 'bg-indigo-50 text-indigo-500']">
                        <i :class="confirmBox.danger ? 'fa-solid fa-triangle-exclamation' : 'fa-regular fa-circle-question'"></i>
                    </div>
                    <h3 class="mb-2 text-[15px] font-semibold text-slate-900">{{ confirmBox.title }}</h3>
                    <p class="mb-6 whitespace-pre-line text-[13px] leading-relaxed text-slate-500">{{ confirmBox.message }}</p>
                    <div class="flex gap-2.5">
                        <button @click="cancelConfirm" class="h-11 flex-1 rounded-xl bg-slate-100 text-[13px] font-medium text-slate-600 transition hover:bg-slate-200">取消</button>
                        <button @click="doConfirm"
                                :class="['h-11 flex-1 rounded-xl text-[13px] font-medium text-white transition active:scale-95',
                                         confirmBox.danger ? 'bg-red-500 shadow-md shadow-red-500/25 hover:bg-red-600' : 'bg-indigo-600 shadow-md shadow-indigo-500/25 hover:bg-indigo-700']">
                            {{ confirmBox.okText }}
                        </button>
                    </div>
                </div>
            </div>
        </transition>
    </div>

    <div class="pointer-events-none fixed left-1/2 top-5 z-[6000] flex w-full max-w-sm -translate-x-1/2 flex-col items-center gap-2 px-4">
        <transition-group name="pop">
            <div v-for="t in toasts" :key="t.id"
                 class="pointer-events-auto flex w-full items-start gap-3 rounded-2xl border border-white/10 bg-slate-900/95 px-4 py-3 shadow-pop backdrop-blur-md">
                <i :class="t.type === 'error' ? 'fa-solid fa-circle-exclamation text-red-400' : t.type === 'info' ? 'fa-solid fa-circle-info text-sky-400' : 'fa-solid fa-circle-check text-emerald-400'"
                   class="mt-0.5 flex-none text-sm"></i>
                <span class="flex-1 text-[13px] font-medium leading-snug text-white">{{ t.msg }}</span>
                <button @click="dismissToast(t.id)" class="flex-none text-slate-500 transition hover:text-white"><i class="fa-solid fa-xmark text-xs"></i></button>
            </div>
        </transition-group>
    </div>

    <input type="file" ref="fileInput" @change="e => handleFiles(e.target.files, false)" class="hidden" multiple>
    <input type="file" ref="folderInput" @change="e => handleFiles(e.target.files, true)" class="hidden" webkitdirectory directory multiple>
</div>

<script>
    const { createApp, ref, onMounted, computed, watch, nextTick } = Vue;

    createApp({
        setup() {
            const serverInitialized = ref(__SERVER_INITIALIZED__);
            const isLoggedIn = ref(false);
            const username = ref('');
            const mobileMenuOpen = ref(false);
            const loading = ref(false);
            const dragActive = ref(false);
            const currentView = ref(localStorage.getItem('fm_current_view') || 'uploads');

            const files = ref([]); const shares = ref([]); const uploadHistory = ref([]); const uploadQueue = ref([]);
            const selectedFiles = ref([]); const currentPath = ref('');
            const selectedShares = ref([]); const isShareSelectionMode = ref(false);
            const trashFiles = ref([]); const selectedTrash = ref([]);
            const stats = ref({ sizeStr: '', count: null });

            const authForm = ref({ username: '', password: '' });
            const authError = ref(''); const authLoading = ref(false);
            const newPassword = ref('');
            const toasts = ref([]); let toastSeq = 0;

            const contextMenu = ref({ visible: false, x: 0, y: 0, file: null, type: 'single' });
            const renameModal = ref({ show: false, oldKey: '', newKey: '' });
            const createFolderModal = ref({ show: false, name: '' });
            const moveModal = ref({ show: false, target: '', folderList: [] });
            const shareConfigModal = ref({ show: false, path: '', password: '', expireHours: '', maxViews: '' });
            const confirmBox = ref({ show: false, title: '', message: '', okText: '确定', danger: false, action: null });
            const lightbox = ref({ show: false, url: '', type: '', name: '' });
            const editor = ref({ show: false, filename: '', content: '', key: '', saving: false, previewMode: false });

            const searchQuery = ref('');
            const viewMode = ref(localStorage.getItem('fm_view_mode') || 'list');
            const isSelectionMode = ref(false);

            const fileInput = ref(null);
            const folderInput = ref(null);
            let processing = false;

            const viewTitle = computed(() => ({
                uploads: '传输中心', files: '全部文件', shares: '分享管理', trash: '回收站', settings: '系统设置'
            })[currentView.value] || 'Cloud Space');

            const checkSession = async () => {
                try {
                    const res = await fetch('/api/session');
                    if (res.ok) {
                        const d = await res.json();
                        serverInitialized.value = true;
                        if (d.authed) { isLoggedIn.value = true; username.value = d.username || '管理员'; await loadCurrentView(); }
                    }
                } catch (e) { /* 离线时保持登录页 */ }
            };

            const loadCurrentView = async () => {
                if (currentView.value === 'uploads') await fetchUploadHistory();
                else if (currentView.value === 'files') await refreshFiles();
                else if (currentView.value === 'shares') await fetchShares();
                else if (currentView.value === 'trash') await fetchTrash();
                else if (currentView.value === 'settings') await fetchStats();
            };

            watch(viewMode, (v) => localStorage.setItem('fm_view_mode', v));
            watch(currentView, (v) => localStorage.setItem('fm_current_view', v));

            const switchView = async (view) => {
                currentView.value = view;
                mobileMenuOpen.value = false;
                closeContextMenu();
                selectedFiles.value = []; isSelectionMode.value = false;
                selectedShares.value = []; isShareSelectionMode.value = false;
                selectedTrash.value = [];
                await loadCurrentView();
            };

            const toggleSelectionMode = () => {
                isSelectionMode.value = !isSelectionMode.value;
                if (!isSelectionMode.value) selectedFiles.value = [];
            };
            const toggleShareSelectionMode = () => {
                isShareSelectionMode.value = !isShareSelectionMode.value;
                if (!isShareSelectionMode.value) selectedShares.value = [];
            };

            const refreshFiles = async () => {
                loading.value = files.value.length === 0;
                try {
                    const res = await fetch('/api/files?prefix=' + encodeURIComponent(currentPath.value));
                    if (res.ok) files.value = await res.json();
                } catch (e) { showToast('文件列表加载失败', 'error'); }
                loading.value = false;
            };
            const fetchTrash = async () => {
                try { const res = await fetch('/api/trash/list'); if (res.ok) trashFiles.value = await res.json(); }
                catch (e) { showToast('回收站加载失败', 'error'); }
            };
            const fetchStats = async () => {
                try {
                    const res = await fetch('/api/stats');
                    if (res.ok) { const d = await res.json(); stats.value = { sizeStr: formatSize(d.totalSize), count: d.count }; }
                } catch (e) { /* 静默 */ }
            };
            const fetchShares = async () => {
                try { const res = await fetch('/api/shares'); if (res.ok) shares.value = await res.json(); }
                catch (e) { showToast('分享列表加载失败', 'error'); }
            };
            const fetchUploadHistory = async () => {
                try { const res = await fetch('/api/uploads/history'); if (res.ok) uploadHistory.value = await res.json(); }
                catch (e) { /* 静默 */ }
            };

            const navigateTo = async (path) => {
                currentPath.value = path;
                selectedFiles.value = [];
                searchQuery.value = '';
                isSelectionMode.value = false;
                await refreshFiles();
            };

            const handleRowClick = (file) => {
                if (isSelectionMode.value) { toggleSelection(file.key); return; }
                if (file.isFolder) { navigateTo(file.key); return; }
                const ext = file.key.split('.').pop().toLowerCase();
                if (['jpg','jpeg','png','gif','webp','avif','bmp','mp4','webm','mov'].includes(ext)) openLightbox(file);
            };

            const openLightbox = (file) => {
                const ext = file.key.split('.').pop().toLowerCase();
                const type = ['mp4','webm','mov'].includes(ext) ? 'video' : 'image';
                lightbox.value = { show: true, url: '/file/' + encodeURIComponent(file.key) + '?mode=inline', type, name: getDisplayName(file.key) };
            };

            const isTextFile = (key) => ['txt','md','markdown','js','mjs','json','html','htm','css','xml','log','yml','yaml','toml','ini','conf','csv','sh','py'].includes(key.split('.').pop().toLowerCase());
            const isMarkdown = computed(() => editor.value.filename.toLowerCase().endsWith('.md') || editor.value.filename.toLowerCase().endsWith('.markdown'));

            const openEditor = async (key) => {
                try {
                    const res = await fetch('/api/text-content?key=' + encodeURIComponent(key));
                    if (!res.ok) return showToast('无法打开该文件', 'error');
                    const text = await res.text();
                    editor.value = { show: true, filename: getDisplayName(key), content: text, key, saving: false, previewMode: false };
                } catch (e) { showToast('读取失败', 'error'); }
            };

            const saveTextContent = async () => {
                editor.value.saving = true;
                try {
                    const res = await fetch('/api/text-content', { method: 'POST', body: JSON.stringify({ key: editor.value.key, content: editor.value.content }) });
                    showToast(res.ok ? '已保存' : '保存失败', res.ok ? 'success' : 'error');
                } catch (e) { showToast('保存出错', 'error'); }
                editor.value.saving = false;
            };

            const compiledMarkdown = computed(() => {
                if (editor.value.previewMode && window.marked) {
                    try { return marked.parse(editor.value.content); } catch (e) { return '<p>解析失败</p>'; }
                }
                return '';
            });

            const pathParts = computed(() => {
                if (!currentPath.value) return [];
                const parts = currentPath.value.split('/').filter(Boolean);
                let accum = '';
                return parts.map(p => { accum += p + '/'; return { name: p, fullPath: accum }; });
            });
            const getDisplayName = (key) => {
                if (key.endsWith('/')) { const p = key.slice(0, -1).split('/'); return p[p.length - 1]; }
                const p = key.split('/'); return p[p.length - 1];
            };

            const sortedFiles = computed(() => {
                let list = files.value.slice();
                if (searchQuery.value) {
                    const q = searchQuery.value.toLowerCase();
                    list = list.filter(f => f.key.toLowerCase().includes(q));
                }
                return list.sort((a, b) => {
                    if (a.isFolder && !b.isFolder) return -1;
                    if (!a.isFolder && b.isFolder) return 1;
                    const cmp = a.isFolder ? a.key.localeCompare(b.key) : (new Date(b.uploaded || 0) - new Date(a.uploaded || 0));
                    return cmp;
                });
            });

            const openMoveModal = async () => {
                moveModal.value = { show: true, target: '', folderList: [] };
                try {
                    const res = await fetch('/api/folders/all');
                    if (res.ok) moveModal.value.folderList = await res.json();
                } catch (e) { /* 静默 */ }
            };
            const confirmMove = async () => {
                let target = moveModal.value.target.trim();
                if (target && !target.endsWith('/')) target += '/';
                const count = selectedFiles.value.length;
                await fetch('/api/move', { method: 'POST', body: JSON.stringify({ keys: selectedFiles.value, targetFolder: target }) });
                moveModal.value.show = false;
                selectedFiles.value = [];
                showToast('已移动 ' + count + ' 项');
                await refreshFiles();
            };
            const createFolder = async () => {
                const name = createFolderModal.value.name.trim();
                if (!name) return;
                await fetch('/api/create-folder', { method: 'POST', body: JSON.stringify({ folderName: name, currentPath: currentPath.value }) });
                createFolderModal.value = { show: false, name: '' };
                showToast('文件夹已创建');
                await refreshFiles();
            };

            const isAllSelected = computed(() => files.value.length > 0 && selectedFiles.value.length === files.value.length);
            const toggleSelectAll = (e) => { selectedFiles.value = e.target.checked ? files.value.map(f => f.key) : []; };
            const toggleSelection = (key) => {
                const idx = selectedFiles.value.indexOf(key);
                if (idx > -1) selectedFiles.value.splice(idx, 1); else selectedFiles.value.push(key);
            };
            const selectAll = () => { selectedFiles.value = files.value.map(f => f.key); };
            const invertSelection = () => {
                const cur = new Set(selectedFiles.value);
                selectedFiles.value = files.value.filter(f => !cur.has(f.key)).map(f => f.key);
            };

            const isAllSharesSelected = computed(() => shares.value.length > 0 && selectedShares.value.length === shares.value.length);
            const selectAllShares = () => { selectedShares.value = shares.value.map(s => s.token); };
            const invertShareSelection = () => {
                const cur = new Set(selectedShares.value);
                selectedShares.value = shares.value.filter(s => !cur.has(s.token)).map(s => s.token);
            };
            const toggleShareSelection = (token) => {
                const idx = selectedShares.value.indexOf(token);
                if (idx > -1) selectedShares.value.splice(idx, 1); else selectedShares.value.push(token);
            };
            const isExpired = (item) => item.expireTime && Date.now() > item.expireTime;

            const batchDeleteShares = () => {
                closeContextMenu();
                if (!selectedShares.value.length) return;
                const tokens = selectedShares.value.slice();
                askConfirm('撤销分享', '确定要撤销选中的 ' + tokens.length + ' 个分享链接吗？\\n撤销后原链接将立即失效。', async () => {
                    await fetch('/api/shares/batch-delete', { method: 'POST', body: JSON.stringify({ tokens }) });
                    selectedShares.value = [];
                    showToast('已撤销 ' + tokens.length + ' 个分享');
                    await fetchShares();
                }, { danger: true, okText: '撤销' });
            };

            const copyText = async (text) => {
                try {
                    if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(text); return true; }
                    const ta = document.createElement('textarea');
                    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
                    document.body.appendChild(ta); ta.select();
                    const ok = document.execCommand('copy');
                    document.body.removeChild(ta);
                    return ok;
                } catch (e) { return false; }
            };

            const batchCopyLinks = async () => {
                closeContextMenu();
                if (!selectedShares.value.length) return;
                const links = selectedShares.value.map(t => window.location.origin + '/s/' + t).join('\\n');
                const ok = await copyText(links);
                showToast(ok ? '已复制 ' + selectedShares.value.length + ' 个链接' : '复制失败，请手动复制', ok ? 'success' : 'error');
            };

            const restoreTrash = async () => {
                if (!selectedTrash.value.length) return;
                const keys = selectedTrash.value.slice();
                await fetch('/api/trash/restore', { method: 'POST', body: JSON.stringify({ keys }) });
                selectedTrash.value = [];
                showToast('已还原 ' + keys.length + ' 项');
                await fetchTrash();
            };
            const deleteTrashForever = () => {
                if (!selectedTrash.value.length) return;
                const keys = selectedTrash.value.slice();
                askConfirm('彻底删除', '将永久删除 ' + keys.length + ' 项，此操作无法撤销。', async () => {
                    await fetch('/api/trash/delete', { method: 'POST', body: JSON.stringify({ keys }) });
                    selectedTrash.value = [];
                    showToast('已彻底删除');
                    await fetchTrash();
                }, { danger: true, okText: '永久删除' });
            };

            const showContextMenu = (e, item, typeOverride) => {
                let x = e.clientX, y = e.clientY;
                if (window.innerWidth - x < 210) x = window.innerWidth - 210;
                if (window.innerHeight - y < 300) y = Math.max(10, window.innerHeight - 300);

                if (typeOverride === 'share') {
                    const batch = selectedShares.value.length > 1 && selectedShares.value.includes(item.token);
                    contextMenu.value = { visible: true, x, y, file: batch ? null : item, type: batch ? 'batch-share' : 'share' };
                    return;
                }
                if (selectedFiles.value.includes(item.key) && selectedFiles.value.length > 1) {
                    contextMenu.value = { visible: true, x, y, file: null, type: 'batch' };
                } else {
                    if (!selectedFiles.value.includes(item.key)) selectedFiles.value = [];
                    contextMenu.value = { visible: true, x, y, file: item, type: 'single' };
                }
            };
            const closeContextMenu = () => { if (contextMenu.value.visible) contextMenu.value.visible = false; };

            const handleMenuAction = (action) => {
                const file = contextMenu.value.file;
                closeContextMenu();
                if (!file) return;
                if (action === 'openShare') window.open('/s/' + file.token, '_blank', 'noopener,noreferrer');
                else if (action === 'copyShare') copyText(window.location.origin + '/s/' + file.token).then(ok => showToast(ok ? '链接已复制' : '复制失败', ok ? 'success' : 'error'));
                else if (action === 'deleteShare') {
                    askConfirm('撤销分享', '撤销后该链接将立即失效，确定继续吗？', async () => {
                        await fetch('/api/shares/delete', { method: 'POST', body: JSON.stringify({ token: file.token }) });
                        showToast('已撤销分享');
                        await fetchShares();
                    }, { danger: true, okText: '撤销' });
                }
                else if (action === 'preview') openLightbox(file);
                else if (action === 'edit') openEditor(file.key);
                else if (action === 'download') window.location.href = '/file/' + encodeURIComponent(file.key) + '?mode=download';
                else if (action === 'rename') renameModal.value = { show: true, oldKey: file.key, newKey: getDisplayName(file.key) };
                else if (action === 'move') { if (!selectedFiles.value.includes(file.key)) selectedFiles.value = [file.key]; openMoveModal(); }
                else if (action === 'share') openShareConfig(file.key);
                else if (action === 'delete') {
                    const isFolder = file.isFolder;
                    askConfirm('移入回收站', '「' + getDisplayName(file.key) + '」' + (isFolder ? '及其全部内容' : '') + '将被移入回收站，可随时还原。', async () => {
                        await fetch('/api/delete-file', { method: 'POST', body: JSON.stringify({ key: file.key }) });
                        showToast('已移入回收站');
                        await refreshFiles();
                    }, { danger: true, okText: '删除' });
                }
            };

            const openShareConfig = (path) => {
                shareConfigModal.value = { show: true, path, password: '', expireHours: '', maxViews: '' };
            };
            const confirmCreateShare = async () => {
                try {
                    const res = await fetch('/api/shares/create', { method: 'POST', body: JSON.stringify(shareConfigModal.value) });
                    const data = await res.json();
                    if (!data.success) return showToast('创建失败', 'error');
                    shareConfigModal.value.show = false;
                    const ok = await copyText(window.location.origin + '/s/' + data.token);
                    showToast(ok ? '分享已创建，链接已复制' : '分享已创建');
                } catch (e) { showToast('创建失败', 'error'); }
            };

            const batchDelete = () => {
                closeContextMenu();
                if (!selectedFiles.value.length) return;
                const keys = selectedFiles.value.slice();
                askConfirm('批量删除', '将 ' + keys.length + ' 个项目移入回收站？\\n可随时从回收站还原。', async () => {
                    await fetch('/api/batch-delete', { method: 'POST', body: JSON.stringify({ keys }) });
                    selectedFiles.value = [];
                    showToast('已移入回收站');
                    await refreshFiles();
                }, { danger: true, okText: '删除' });
            };

            const confirmRename = async () => {
                const { oldKey, newKey } = renameModal.value;
                const name = (newKey || '').trim();
                renameModal.value.show = false;
                if (!name) return;
                const parts = oldKey.split('/'); parts.pop();
                const prefix = parts.length ? parts.join('/') + '/' : '';
                const newFullPath = prefix + name;
                if (newFullPath === oldKey) return;
                await fetch('/api/rename', { method: 'POST', body: JSON.stringify({ oldKey, newKey: newFullPath }) });
                showToast('重命名成功');
                await refreshFiles();
            };

            const pickFiles = () => { if (fileInput.value) fileInput.value.click(); };
            const pickFolder = () => { if (folderInput.value) folderInput.value.click(); };

            const handleFiles = (fileList, fromFolder) => {
                const list = Array.from(fileList || []);
                if (!list.length) return;
                for (const file of list) {
                    const relativePath = fromFolder && file.webkitRelativePath ? file.webkitRelativePath : (file.webkitRelativePath || file.customRelativePath || file.name);
                    uploadQueue.value.push({ id: Date.now() + Math.random(), file, relativePath, progress: 0, status: 'pending', statusText: '等待中' });
                }
                processQueue();
                if (currentView.value !== 'uploads') switchView('uploads');
                showToast('已加入上传队列，共 ' + list.length + ' 个文件', 'info');
            };

            const handleDrop = async (e) => {
                dragActive.value = false;
                const items = e.dataTransfer && e.dataTransfer.items;
                if (!items || !items.length) {
                    if (e.dataTransfer && e.dataTransfer.files) handleFiles(e.dataTransfer.files, false);
                    return;
                }
                const files = [];
                const traverse = (entry, path) => new Promise((resolve) => {
                    if (!entry) return resolve();
                    if (entry.isFile) {
                        entry.file((f) => { f.customRelativePath = path + f.name; files.push(f); resolve(); }, resolve);
                    } else if (entry.isDirectory) {
                        const reader = entry.createReader();
                        const readBatch = () => {
                            reader.readEntries(async (entries) => {
                                if (!entries.length) return resolve();
                                await Promise.all(entries.map(en => traverse(en, path + entry.name + '/')));
                                readBatch();
                            }, resolve);
                        };
                        readBatch();
                    } else resolve();
                });
                const roots = [];
                for (let i = 0; i < items.length; i++) {
                    const entry = items[i].webkitGetAsEntry && items[i].webkitGetAsEntry();
                    if (entry) roots.push(traverse(entry, ''));
                }
                await Promise.all(roots);
                if (files.length) handleFiles(files, true);
            };

            const processQueue = async () => {
                if (processing) return;
                const item = uploadQueue.value.find(i => i.status === 'pending');
                if (!item) return;
                processing = true;
                item.status = 'uploading'; item.statusText = '上传中';
                try {
                    await uploadItem(item);
                    item.status = 'success'; item.statusText = '完成'; item.progress = 100;
                } catch (err) {
                    item.status = 'error'; item.statusText = '失败';
                } finally {
                    processing = false;
                    fetchUploadHistory();
                    processQueue();
                }
            };

            const uploadItem = (item) => new Promise((resolve, reject) => {
                const fd = new FormData();
                fd.append('file', item.file);
                fd.append('folder', currentPath.value);
                fd.append('relativePath', item.relativePath);
                const xhr = new XMLHttpRequest();
                xhr.open('POST', '/api/upload', true);
                xhr.upload.onprogress = (e) => { if (e.lengthComputable) item.progress = Math.round((e.loaded / e.total) * 100); };
                xhr.onload = () => (xhr.status >= 200 && xhr.status < 300) ? resolve() : reject(new Error(String(xhr.status)));
                xhr.onerror = () => reject(new Error('network'));
                xhr.send(fd);
            });

            const clearQueue = () => { uploadQueue.value = uploadQueue.value.filter(i => i.status === 'uploading' || i.status === 'pending'); };
            const clearUploadHistory = () => {
                askConfirm('清空上传记录', '仅清除历史列表，不会删除任何实际文件。', async () => {
                    await fetch('/api/uploads/clear-history', { method: 'POST' });
                    uploadHistory.value = [];
                    showToast('记录已清空');
                }, { okText: '清空' });
            };

            const handleAuth = async () => {
                authError.value = '';
                if (!authForm.value.username.trim()) { authError.value = '请输入用户名'; return; }
                if (authForm.value.password.length < 6) { authError.value = '密码至少 6 位'; return; }
                authLoading.value = true;
                const wasInitialized = serverInitialized.value;
                try {
                    const endpoint = wasInitialized ? '/api/login' : '/api/setup';
                    const res = await fetch(endpoint, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username: authForm.value.username.trim(), password: authForm.value.password })
                    });
                    let data = {};
                    try { data = await res.json(); } catch (e) { data = {}; }
                    if (res.ok && data.success) {
                        serverInitialized.value = true;
                        username.value = authForm.value.username.trim();
                        authForm.value.password = '';
                        isLoggedIn.value = true;
                        await loadCurrentView();
                        showToast(wasInitialized ? '欢迎回来' : '初始化完成');
                    } else {
                        authError.value = data.msg || (res.status === 429 ? '尝试过于频繁，请稍后再试' : '用户名或密码错误');
                    }
                } catch (e) { authError.value = '网络异常，请稍后重试'; }
                authLoading.value = false;
            };

            const logout = async () => {
                try { await fetch('/api/logout', { method: 'POST' }); } catch (e) { /* 忽略 */ }
                isLoggedIn.value = false;
                username.value = '';
                files.value = []; shares.value = []; trashFiles.value = []; uploadQueue.value = [];
                selectedFiles.value = []; selectedShares.value = []; selectedTrash.value = [];
                currentPath.value = '';
            };

            const updatePassword = () => {
                if (newPassword.value.length < 6) return;
                askConfirm('修改密码', '修改后所有设备上的登录状态将被注销，需要用新密码重新登录。', async () => {
                    const res = await fetch('/api/settings/password', { method: 'POST', body: JSON.stringify({ password: newPassword.value }) });
                    if (res.ok) { newPassword.value = ''; showToast('密码已更新'); }
                    else { let m = '修改失败'; try { m = (await res.json()).msg || m; } catch (e) {} showToast(m, 'error'); }
                }, { okText: '确认修改' });
            };

            const showToast = (msg, type) => {
                const id = ++toastSeq;
                toasts.value.push({ id, msg, type: type || 'success' });
                setTimeout(() => dismissToast(id), 3600);
            };
            const dismissToast = (id) => { toasts.value = toasts.value.filter(t => t.id !== id); };

            const askConfirm = (title, message, action, opts) => {
                const o = opts || {};
                confirmBox.value = { show: true, title, message, okText: o.okText || '确定', danger: !!o.danger, action };
            };
            const doConfirm = async () => {
                const action = confirmBox.value.action;
                confirmBox.value.show = false;
                if (typeof action === 'function') await action();
            };
            const cancelConfirm = () => { confirmBox.value.show = false; };

            const formatSize = (bytes) => {
                if (!bytes) return '0 B';
                const k = 1024, i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), 4);
                return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + ['B','KB','MB','GB','TB'][i];
            };
            const formatDate = (d) => {
                if (!d) return '—';
                const date = new Date(d);
                if (isNaN(date.getTime())) return '—';
                const now = new Date();
                const sameDay = date.toDateString() === now.toDateString();
                if (sameDay) return date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
                const sameYear = date.getFullYear() === now.getFullYear();
                return date.toLocaleDateString('zh-CN', sameYear ? { month: '2-digit', day: '2-digit' } : { year: 'numeric', month: '2-digit', day: '2-digit' });
            };
            const getFileIcon = (file) => {
                if (file.isFolder) return 'fa-regular fa-folder';
                const ext = file.key.split('.').pop().toLowerCase();
                if (['jpg','jpeg','png','gif','webp','avif','bmp','svg'].includes(ext)) return 'fa-regular fa-image';
                if (['mp4','mov','webm','mkv','avi'].includes(ext)) return 'fa-regular fa-file-video';
                if (['mp3','wav','flac','m4a','ogg'].includes(ext)) return 'fa-regular fa-file-audio';
                if (ext === 'pdf') return 'fa-regular fa-file-pdf';
                if (['zip','rar','7z','tar','gz'].includes(ext)) return 'fa-regular fa-file-zipper';
                if (['doc','docx'].includes(ext)) return 'fa-regular fa-file-word';
                if (['xls','xlsx','csv'].includes(ext)) return 'fa-regular fa-file-excel';
                if (['ppt','pptx'].includes(ext)) return 'fa-regular fa-file-powerpoint';
                if (['js','mjs','json','html','htm','css','xml','yml','yaml','py','sh','ts'].includes(ext)) return 'fa-regular fa-file-code';
                if (['txt','md','markdown','log'].includes(ext)) return 'fa-regular fa-file-lines';
                return 'fa-regular fa-file';
            };
            const fileTint = (file) => {
                const ext = file.key.split('.').pop().toLowerCase();
                if (['jpg','jpeg','png','gif','webp','avif','bmp','svg'].includes(ext)) return 'bg-sky-50 text-sky-500';
                if (['mp4','mov','webm','mkv','avi'].includes(ext)) return 'bg-violet-50 text-violet-500';
                if (['mp3','wav','flac','m4a','ogg'].includes(ext)) return 'bg-pink-50 text-pink-500';
                if (ext === 'pdf') return 'bg-red-50 text-red-500';
                if (['zip','rar','7z','tar','gz'].includes(ext)) return 'bg-amber-50 text-amber-500';
                if (['js','mjs','json','html','htm','css','xml','yml','yaml','py','sh','ts'].includes(ext)) return 'bg-emerald-50 text-emerald-500';
                return 'bg-slate-100 text-slate-500';
            };
            const activeUploadCount = computed(() => uploadQueue.value.filter(i => i.status === 'uploading' || i.status === 'pending').length);

            onMounted(async () => {
                window.addEventListener('click', closeContextMenu);
                window.addEventListener('contextmenu', (e) => {
                    if (!e.target.closest('tr') && !e.target.closest('.card-hover')) closeContextMenu();
                });
                document.addEventListener('keydown', (e) => {
                    if (e.key === 'Escape') {
                        closeContextMenu();
                        if (confirmBox.value.show) cancelConfirm();
                        else if (lightbox.value.show) lightbox.value.show = false;
                    }
                });
                await checkSession();
            });

            return {
                serverInitialized, isLoggedIn, username, mobileMenuOpen, currentView, viewTitle, loading, dragActive,
                files, shares, uploadQueue, uploadHistory, activeUploadCount, selectedFiles, isAllSelected, currentPath, pathParts,
                selectedShares, isShareSelectionMode, isAllSharesSelected, selectAllShares, invertShareSelection, toggleShareSelection, toggleShareSelectionMode, batchDeleteShares, batchCopyLinks,
                trashFiles, selectedTrash, restoreTrash, deleteTrashForever, stats,
                authForm, authError, authLoading, newPassword, toasts, dismissToast,
                contextMenu, renameModal, createFolderModal, moveModal, shareConfigModal, confirmBox, lightbox, editor,
                searchQuery, sortedFiles, viewMode, isSelectionMode, compiledMarkdown, isMarkdown,
                handleAuth, logout, switchView, handleFiles, handleDrop, pickFiles, pickFolder, clearQueue, fileInput, folderInput,
                refreshFiles, fetchShares, fetchTrash, fetchStats, updatePassword,
                showContextMenu, closeContextMenu, handleMenuAction, confirmRename, createFolder, confirmMove, openMoveModal,
                toggleSelectAll, toggleSelection, batchDelete, navigateTo, handleRowClick, getDisplayName,
                openShareConfig, confirmCreateShare, fetchUploadHistory, clearUploadHistory,
                formatSize, formatDate, getFileIcon, fileTint, openLightbox, openEditor, saveTextContent, isTextFile,
                toggleSelectionMode, selectAll, invertSelection, isExpired, askConfirm, doConfirm, cancelConfirm, showToast
            };
        }
    }).mount('#app');
</script>
</body>
</html>
`.replace('__SERVER_INITIALIZED__', String(isInitialized));
}
