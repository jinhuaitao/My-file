/**
 * Cloudflare Worker File Manager (Clean UI Edition)
 * Version: 3.1.0 (No Sidebar Buttons + Recursive Drop)
 */

const CONFIG_KEY = '.sys_config.json';
const SHARES_KEY = '.sys_shares.json';
const UPLOADS_KEY = '.sys_uploads.json';
const SESSION_KEY = 'auth_session';

const SECURE_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const range = request.headers.get('Range');

    // --- 0. 核心工具 ---
    const getJson = async (key) => {
        const obj = await env.MY_BUCKET.get(key);
        return obj ? await obj.json() : null;
    };
    const saveJson = async (key, data) => {
        await env.MY_BUCKET.put(key, JSON.stringify(data));
    };

    // --- 1. 公开：分享链接 ---
    if (path.startsWith('/s/')) {
        const token = path.replace('/s/', '');
        const shares = (await getJson(SHARES_KEY)) || {};
        const share = shares[token];

        if (!share) return new Response(getErrorPageHtml('链接无效', '该分享链接不存在或已被删除。'), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
        if (share.expireTime && Date.now() > share.expireTime) return new Response(getErrorPageHtml('链接已过期', '该分享链接已超过有效期。'), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
        if (share.maxViews && (share.views || 0) >= share.maxViews) return new Response(getErrorPageHtml('访问次数耗尽', '该分享链接已达到最大访问次数限制。'), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });

        const fileName = share.path;
        const inputPassword = url.searchParams.get('pwd');
        const mode = url.searchParams.get('mode');

        if (share.password && share.password !== inputPassword) {
            return new Response(getPasswordPageHtml(token, !!inputPassword), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
        }

        const getOpts = {};
        const ifMatchHeader = request.headers.get('if-match');
        if (range) getOpts.range = range;
        if (ifMatchHeader) getOpts.onlyIf = { etag: ifMatchHeader };

        const object = await env.MY_BUCKET.get(fileName, getOpts);
        if (!object) return new Response(getErrorPageHtml('文件丢失', '源文件可能已被删除。'), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });

        if (mode !== 'inline' && !range) {
            share.views = (share.views || 0) + 1;
            ctx.waitUntil(saveJson(SHARES_KEY, shares));
        }

        const headers = new Headers(SECURE_HEADERS);
        object.writeHttpMetadata(headers);
        headers.set('etag', object.httpEtag);
        
        if (range && object.range) {
            headers.set('content-range', `bytes ${object.range.offset}-${object.range.end}/${object.size}`);
            headers.set('content-length', object.range.end - object.range.offset + 1);
            return new Response(object.body, { headers, status: 206 });
        }

        if (mode === 'download') {
            headers.set('Content-Disposition', `attachment; filename="${fileName.split('/').pop()}"`);
            return new Response(object.body, { headers });
        }
        
        if (mode === 'inline') {
            headers.set('Content-Disposition', `inline; filename="${fileName.split('/').pop()}"`);
            return new Response(object.body, { headers });
        }

        return new Response(getSharePageHtml(fileName.split('/').pop(), object.size, token, object.httpMetadata?.contentType, share.password), { 
            headers: { 'Content-Type': 'text/html;charset=UTF-8' } 
        });
    }

    // --- 2. 鉴权与初始化 ---
    const config = await getJson(CONFIG_KEY);
    const isInitialized = config !== null;

    if (path === '/api/setup' && method === 'POST') {
        if (isInitialized) return new Response('Forbidden', { status: 403 });
        const data = await request.json();
        await saveJson(CONFIG_KEY, { username: data.username, password: await hashText(data.password) });
        await saveJson(SHARES_KEY, {});
        await saveJson(UPLOADS_KEY, []);
        return new Response(JSON.stringify({ success: true }));
    }

    if (path === '/api/login' && method === 'POST') {
        if (!isInitialized) return new Response('Not initialized', { status: 400 });
        const data = await request.json();
        const inputHash = await hashText(data.password);
        if (data.username === config.username && inputHash === config.password) {
            const sessionVal = btoa(`${config.username}|${config.password}`);
            return new Response(JSON.stringify({ success: true }), {
                headers: { 'Set-Cookie': `${SESSION_KEY}=${sessionVal}; Path=/; Max-Age=604800; SameSite=Strict; Secure` }
            });
        }
        return new Response(JSON.stringify({ success: false, msg: 'Error' }), { status: 401 });
    }

    const cookie = request.headers.get('Cookie');
    const authValid = await checkAuth(cookie, config);

    if (!authValid) {
        if (path.startsWith('/api/')) return new Response('Unauthorized', { status: 401 });
        return new Response(getHtml(isInitialized), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }

    // --- 3. 业务 API ---

    if (path === '/api/stats' && method === 'GET') {
        let totalSize = 0;
        let count = 0;
        let truncated = true;
        let cursor = undefined;
        while(truncated) {
            const res = await env.MY_BUCKET.list({ cursor });
            truncated = res.truncated;
            cursor = res.cursor;
            res.objects.forEach(o => {
                if(!o.key.startsWith('.sys_')) {
                    totalSize += o.size;
                    count++;
                }
            });
        }
        return new Response(JSON.stringify({ totalSize, count }));
    }

    if (path === '/api/text-content' && method === 'GET') {
        const key = url.searchParams.get('key');
        if(!key) return new Response('Missing key', {status: 400});
        const obj = await env.MY_BUCKET.get(key);
        if(!obj) return new Response('Not found', {status: 404});
        return new Response(obj.body, { headers: {'Content-Type': 'text/plain'} });
    }

    if (path === '/api/text-content' && method === 'POST') {
        const { key, content } = await request.json();
        if(!key) return new Response('Missing key', {status: 400});
        await env.MY_BUCKET.put(key, content, { httpMetadata: { contentType: getMimeType(key) } });
        return new Response(JSON.stringify({ success: true }));
    }

    if (path === '/api/files' && method === 'GET') {
        const prefix = url.searchParams.get('prefix') || '';
        const list = await env.MY_BUCKET.list({ prefix: prefix, delimiter: '/' });
        const folders = list.delimitedPrefixes.map(p => ({ key: p, isFolder: true }));
        const files = list.objects
            .filter(o => !o.key.startsWith('.sys_'))
            .filter(o => o.key !== prefix)
            .map(o => ({ key: o.key, size: o.size, uploaded: o.uploaded, isFolder: false }));
        return new Response(JSON.stringify([...folders, ...files]));
    }

    if (path === '/api/folders/all' && method === 'GET') {
        const scanFolders = async (prefix = '') => {
            let folders = [];
            let truncated = true;
            let cursor = undefined;
            while(truncated) {
                const res = await env.MY_BUCKET.list({ prefix, delimiter: '/', cursor });
                truncated = res.truncated;
                cursor = res.cursor;
                for (const p of res.delimitedPrefixes) {
                    folders.push(p);
                    const subs = await scanFolders(p);
                    folders = folders.concat(subs);
                }
            }
            return folders;
        };
        const allFolders = await scanFolders('');
        return new Response(JSON.stringify(allFolders));
    }

    if (path === '/api/create-folder' && method === 'POST') {
        const { folderName, currentPath } = await request.json();
        const fullPath = currentPath + folderName + '/';
        await env.MY_BUCKET.put(fullPath, new Uint8Array(0));
        return new Response(JSON.stringify({ success: true }));
    }

    if (path === '/api/move' && method === 'POST') {
        const { keys, targetFolder } = await request.json();
        for (const oldKey of keys) {
            const fileName = oldKey.split('/').pop();
            const newKey = targetFolder + fileName;
            if (oldKey === newKey) continue;
            const oldObj = await env.MY_BUCKET.get(oldKey);
            if (oldObj) {
                await env.MY_BUCKET.put(newKey, oldObj.body, { httpMetadata: oldObj.httpMetadata });
                await env.MY_BUCKET.delete(oldKey);
                const shares = (await getJson(SHARES_KEY)) || {};
                let updated = false;
                for(let k in shares) { if(shares[k].path === oldKey) { shares[k].path = newKey; updated = true; } }
                if(updated) await saveJson(SHARES_KEY, shares);
            }
        }
        return new Response(JSON.stringify({ success: true }));
    }

    // --- Upload API (Modified for relative paths) ---
    if (path === '/api/upload' && method === 'POST') {
        const formData = await request.formData();
        const file = formData.get('file');
        const folder = formData.get('folder') || '';
        const relativePath = formData.get('relativePath') || file.name;

        if(!file) return new Response('No file', {status: 400});
        
        const fullKey = folder + relativePath;
        
        await env.MY_BUCKET.put(fullKey, file.stream(), { httpMetadata: { contentType: file.type } });
        try {
            let history = (await getJson(UPLOADS_KEY)) || [];
            if(!Array.isArray(history)) history = [];
            history.unshift({ name: fullKey, size: file.size, date: new Date().toISOString() });
            if(history.length > 100) history = history.slice(0, 100);
            await saveJson(UPLOADS_KEY, history);
        } catch(e) {}
        return new Response(JSON.stringify({ success: true }));
    }

    if (path === '/api/rename' && method === 'POST') {
        const { oldKey, newKey } = await request.json();
        const oldObj = await env.MY_BUCKET.get(oldKey);
        if (oldObj) {
            await env.MY_BUCKET.put(newKey, oldObj.body, { httpMetadata: oldObj.httpMetadata });
            await env.MY_BUCKET.delete(oldKey);
            try {
                let history = (await getJson(UPLOADS_KEY)) || [];
                let histUpdated = false;
                history = history.map(h => { if(h.name === oldKey) { h.name = newKey; histUpdated = true; } return h; });
                if(histUpdated) await saveJson(UPLOADS_KEY, history);
            } catch(e) {}
            
            const shares = (await getJson(SHARES_KEY)) || {};
            let updated = false;
            for(let k in shares) { if(shares[k].path === oldKey) { shares[k].path = newKey; updated = true; } }
            if(updated) await saveJson(SHARES_KEY, shares);
        }
        return new Response(JSON.stringify({ success: true }));
    }

    // --- 修复后的删除逻辑 (支持递归删除文件夹) ---
    
    // 定义一个内部删除函数，统一处理单文件和文件夹
    const deleteItemRecursively = async (targetKey) => {
        // 判断是否为文件夹 (以 / 结尾)
        if (targetKey.endsWith('/')) {
            // 如果是文件夹，循环列出该前缀下的所有文件
            let truncated = true;
            let cursor = undefined;
            while(truncated) {
                const res = await env.MY_BUCKET.list({ prefix: targetKey, cursor });
                truncated = res.truncated;
                cursor = res.cursor;
                
                // 遍历所有子文件，移动到回收站并删除源文件
                for (const o of res.objects) {
                    const trashKey = `.sys_trash/${o.key}`;
                    const obj = await env.MY_BUCKET.get(o.key);
                    if (obj) {
                        await env.MY_BUCKET.put(trashKey, obj.body, { httpMetadata: obj.httpMetadata });
                        await env.MY_BUCKET.delete(o.key);
                    }
                }
            }
        } else {
            // 如果是普通文件，直接处理
            const trashKey = `.sys_trash/${targetKey}`;
            const obj = await env.MY_BUCKET.get(targetKey);
            if (obj) {
                await env.MY_BUCKET.put(trashKey, obj.body, { httpMetadata: obj.httpMetadata });
                await env.MY_BUCKET.delete(targetKey);
            }
        }
    };

    if (path === '/api/delete-file' && method === 'POST') {
        const { key } = await request.json();
        await deleteItemRecursively(key);
        return new Response(JSON.stringify({ success: true }));
    }

    if (path === '/api/batch-delete' && method === 'POST') {
        const { keys } = await request.json();
        for (const key of keys) {
            await deleteItemRecursively(key);
        }
        return new Response(JSON.stringify({ success: true }));
    }

    if (path === '/api/trash/list' && method === 'GET') {
        let truncated = true; 
        let cursor = undefined;
        let files = [];
        const list = await env.MY_BUCKET.list({ prefix: '.sys_trash/', include: ['customMetadata'], limit: 500 });
        files = list.objects.map(o => ({
            key: o.key,
            originalPath: o.key.replace('.sys_trash/', ''),
            size: o.size,
            deletedAt: o.uploaded
        }));
        return new Response(JSON.stringify(files));
    }

    if (path === '/api/trash/restore' && method === 'POST') {
        const { keys } = await request.json();
        for (const trashKey of keys) {
            const originalKey = trashKey.replace('.sys_trash/', '');
            const obj = await env.MY_BUCKET.get(trashKey);
            if (obj) {
                await env.MY_BUCKET.put(originalKey, obj.body, { httpMetadata: obj.httpMetadata });
                await env.MY_BUCKET.delete(trashKey);
            }
        }
        return new Response(JSON.stringify({ success: true }));
    }

    if (path === '/api/trash/delete' && method === 'POST') {
        const { keys } = await request.json();
        await Promise.all(keys.map(key => env.MY_BUCKET.delete(key)));
        return new Response(JSON.stringify({ success: true }));
    }

    if (path === '/api/uploads/history' && method === 'GET') {
        const history = (await getJson(UPLOADS_KEY)) || [];
        return new Response(JSON.stringify(history));
    }
    
    if (path === '/api/uploads/clear-history' && method === 'POST') {
        await saveJson(UPLOADS_KEY, []);
        return new Response(JSON.stringify({ success: true }));
    }

    if (path === '/api/shares' && method === 'GET') {
        const shares = (await getJson(SHARES_KEY)) || {};
        return new Response(JSON.stringify(Object.entries(shares).map(([token, info]) => ({ token, ...info }))));
    }
    
    if (path === '/api/shares/create' && method === 'POST') {
        const { path: filePath, password, expireHours, maxViews } = await request.json();
        const shares = (await getJson(SHARES_KEY)) || {};
        const token = crypto.randomUUID().split('-')[0];
        const shareData = { path: filePath, created: new Date().toISOString(), views: 0 };
        if (password) shareData.password = password;
        if (maxViews) shareData.maxViews = parseInt(maxViews);
        if (expireHours) shareData.expireTime = Date.now() + (parseInt(expireHours) * 60 * 60 * 1000);
        shares[token] = shareData;
        await saveJson(SHARES_KEY, shares);
        return new Response(JSON.stringify({ success: true, token }));
    }

    if (path === '/api/shares/delete' && method === 'POST') {
        const { token } = await request.json();
        const shares = (await getJson(SHARES_KEY)) || {};
        delete shares[token];
        await saveJson(SHARES_KEY, shares);
        return new Response(JSON.stringify({ success: true }));
    }

    if (path === '/api/shares/batch-delete' && method === 'POST') {
        const { tokens } = await request.json();
        const shares = (await getJson(SHARES_KEY)) || {};
        tokens.forEach(t => delete shares[t]);
        await saveJson(SHARES_KEY, shares);
        return new Response(JSON.stringify({ success: true }));
    }

    if (path.startsWith('/file/')) {
        const key = decodeURIComponent(path.replace('/file/', '').split('?')[0]);
        
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
            headers.set('content-range', `bytes ${object.range.offset}-${object.range.end}/${object.size}`);
            headers.set('content-length', object.range.end - object.range.offset + 1);
            return new Response(object.body, { headers, status: 206 });
        }

        const mode = url.searchParams.get('mode');
        const fileName = key.split('/').pop();
        headers.set('Content-Disposition', mode === 'download' ? `attachment; filename="${fileName}"` : `inline; filename="${fileName}"`);
        return new Response(object.body, { headers });
    }

    if (path === '/api/settings/password' && method === 'POST') {
        const { password } = await request.json();
        config.password = await hashText(password);
        await saveJson(CONFIG_KEY, config);
        return new Response(JSON.stringify({ success: true }));
    }

    return new Response(getHtml(isInitialized), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }
};

function getMimeType(key) {
    const ext = key.split('.').pop().toLowerCase();
    const map = { 'txt': 'text/plain', 'html': 'text/html', 'css': 'text/css', 'js': 'application/javascript', 'json': 'application/json', 'xml': 'application/xml', 'md': 'text/markdown' };
    return map[ext] || 'application/octet-stream';
}

async function hashText(text) {
    const msgUint8 = new TextEncoder().encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function checkAuth(cookieStr, config) {
    if (!cookieStr || !config) return false;
    const cookies = {};
    cookieStr.split(';').forEach(c => { const [k, v] = c.trim().split('='); cookies[k] = v; });
    const session = cookies[SESSION_KEY];
    if (!session) return false;
    try {
        const [u, p] = atob(session).split('|');
        return (u === config.username && p === config.password);
    } catch { return false; }
}

function getErrorPageHtml(title, msg) { return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${title}</title><script src="https://cdn.tailwindcss.com"></script><link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet"></head><body class="bg-gray-100 h-screen flex flex-col items-center justify-center p-4"><div class="bg-white rounded-2xl shadow-xl p-8 max-w-sm text-center"><div class="text-5xl text-gray-300 mb-4"><i class="fa-regular fa-face-frown"></i></div><h1 class="text-xl font-bold text-gray-800 mb-2">${title}</h1><p class="text-gray-500 text-sm">${msg}</p></div></body></html>`; }

function getPasswordPageHtml(token, isWrong) { return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>密码保护</title><script src="https://cdn.tailwindcss.com"></script><link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet"><link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet"><style>body{font-family:'Inter',sans-serif;}</style></head><body class="bg-slate-50 h-screen flex flex-col items-center justify-center p-4"><div class="bg-white rounded-3xl shadow-xl w-full max-w-sm overflow-hidden ring-1 ring-slate-900/5"><div class="bg-slate-900 p-8 text-center text-white"><div class="text-4xl mb-3 text-blue-400"><i class="fa-solid fa-lock"></i></div><h1 class="font-bold text-lg tracking-wide">文件已加密</h1><p class="text-slate-400 text-xs mt-1">请输入密码以继续访问</p></div><div class="p-8"><form action="/s/${token}" method="GET"><div class="mb-6"><label class="block text-xs font-bold text-slate-500 uppercase mb-2">访问密码</label><input type="password" name="pwd" class="w-full px-4 py-3 bg-slate-50 border ${isWrong ? 'border-red-500 ring-1 ring-red-500' : 'border-slate-200'} rounded-xl focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none transition" placeholder="Enter password" required>${isWrong ? '<p class="text-red-500 text-xs mt-2 font-medium"><i class="fa-solid fa-circle-exclamation"></i> 密码错误</p>' : ''}</div><button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3.5 rounded-xl transition shadow-lg shadow-blue-200 active:scale-95">查看文件</button></form></div></div></body></html>`; }

function getSharePageHtml(fileName, size, token, type, password) {
    const isImage = type && type.startsWith('image/');
    const isVideo = type && type.startsWith('video/');
    const formatSize = (bytes) => { if (bytes === 0) return '0 B'; const k = 1024; const i = Math.floor(Math.log(bytes) / Math.log(k)); return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + ['B', 'KB', 'MB', 'GB', 'TB'][i]; };
    const pwdParam = password ? `&pwd=${encodeURIComponent(password)}` : '';
    
    return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${fileName}</title><script src="https://cdn.tailwindcss.com"></script><link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet"><link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet"><style>body{font-family:'Inter',sans-serif;}</style></head><body class="bg-slate-50 h-screen flex flex-col items-center justify-center p-4">
    <div class="bg-white/80 backdrop-blur-xl rounded-3xl shadow-[0_20px_40px_-15px_rgba(0,0,0,0.1)] w-full max-w-lg overflow-hidden border border-white/50 ring-1 ring-slate-900/5">
        <div class="p-10 text-center">
            <div class="w-20 h-20 mx-auto bg-blue-50 text-blue-500 rounded-2xl flex items-center justify-center text-4xl mb-6 shadow-sm">
                <i class="${isImage ? 'fa-regular fa-image' : (isVideo ? 'fa-regular fa-file-video' : 'fa-regular fa-file')}"></i>
            </div>
            <h1 class="text-xl font-semibold text-slate-800 truncate px-4 mb-2" title="${fileName}">${fileName}</h1>
            <p class="text-slate-400 text-sm font-medium tracking-wide uppercase">${formatSize(size)}</p>
        </div>
        <div class="px-8 pb-8">
            ${isImage ? `<div class="mb-6 rounded-2xl overflow-hidden bg-slate-100 border border-slate-200 flex items-center justify-center shadow-inner"><img src="/s/${token}?mode=inline${pwdParam}" class="max-w-full h-auto max-h-64 object-contain"></div>` : ''}
            ${isVideo ? `<div class="mb-6 rounded-2xl overflow-hidden bg-black shadow-lg"><video src="/s/${token}?mode=inline${pwdParam}" controls class="w-full max-h-64"></video></div>` : ''}
            <a href="/s/${token}?mode=download${pwdParam}" class="group block w-full bg-slate-900 hover:bg-slate-800 text-white text-center font-medium py-3.5 rounded-xl transition-all shadow-lg shadow-slate-300/50 hover:shadow-slate-400/50 active:scale-[0.98] flex items-center justify-center gap-2">
                <i class="fa-solid fa-cloud-arrow-down group-hover:animate-bounce"></i> 立即下载
            </a>
            <p class="text-center text-slate-300 text-xs mt-6 font-medium">Secure File Transfer</p>
        </div>
    </div></body></html>`;
}

function getHtml(isInitialized) {
  return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Cloud Space</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/vue/3.3.4/vue.global.prod.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    fontFamily: { sans: ['Inter', 'sans-serif'] },
                    colors: { gray: { 750: '#2d3748' } },
                    typography: (theme) => ({
                        DEFAULT: { css: { color: theme('colors.slate.700'), maxWidth: 'none' } }
                    })
                }
            },
            plugins: []
        }
    </script>
    <style>
        ::-webkit-scrollbar { width: 0px; background: transparent; }
        .scroll-visible::-webkit-scrollbar { width: 5px; }
        .scroll-visible::-webkit-scrollbar-track { background: transparent; }
        .scroll-visible::-webkit-scrollbar-thumb { background: rgba(156, 163, 175, 0.3); border-radius: 10px; }
        
        .glass-panel { background: rgba(255, 255, 255, 0.75); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.5); }
        .glass-sidebar { background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); }
        
        .sidebar-item { transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1); position: relative; overflow: hidden; }
        .sidebar-item::before { content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 3px; background: #60a5fa; transform: scaleY(0); transition: transform 0.2s; border-radius: 0 4px 4px 0; }
        .sidebar-item.active { background: rgba(255,255,255,0.08); color: white; }
        .sidebar-item.active::before { transform: scaleY(1); }
        
        .checkbox-wrapper input[type="checkbox"] { 
            appearance: none; width: 1.2rem; height: 1.2rem; border-radius: 6px; border: 1.5px solid #cbd5e1; background: white; transition: all 0.2s; position: relative; cursor: pointer;
        }
        .checkbox-wrapper input[type="checkbox"]:checked { background: #3b82f6; border-color: #3b82f6; }
        .checkbox-wrapper input[type="checkbox"]:checked::after { content: '\\f00c'; font-family: 'Font Awesome 6 Free'; font-weight: 900; color: white; font-size: 0.7rem; position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); }

        .context-menu { position: fixed; z-index: 5000; background: rgba(255, 255, 255, 0.9); backdrop-filter: blur(16px); border-radius: 12px; box-shadow: 0 10px 30px -5px rgba(0,0,0,0.15); border: 1px solid rgba(255,255,255,0.6); overflow: hidden; min-width: 180px; animation: menuScale 0.15s ease-out; transform-origin: top left; }
        @keyframes menuScale { from { opacity: 0; transform: scale(0.95); } to { opacity: 1; transform: scale(1); } }
        .context-menu-item { padding: 10px 16px; cursor: pointer; display: flex; align-items: center; gap: 12px; font-size: 13.5px; color: #475569; font-weight: 500; transition: all 0.1s; }
        .context-menu-item:hover { background-color: #3b82f6; color: white; }
        .context-menu-item:hover i { color: white !important; }
        
        .folder-grid-item { transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1); }
        .folder-grid-item:hover { transform: translateY(-4px); box-shadow: 0 12px 24px -8px rgba(0,0,0,0.1); }
        .folder-grid-item:active { transform: scale(0.98); }

        .fade-enter-active, .fade-leave-active { transition: opacity 0.2s ease; }
        .fade-enter-from, .fade-leave-to { opacity: 0; }
        .slide-up-enter-active, .slide-up-leave-active { transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1); }
        .slide-up-enter-from, .slide-up-leave-to { transform: translateY(100%); opacity: 0; }
        .modal-enter-active, .modal-leave-active { transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1); }
        .modal-enter-from, .modal-leave-to { opacity: 0; transform: scale(0.95) translateY(10px); }

        /* Prose minimal for markdown */
        .prose h1 { font-size: 1.5em; margin-top: 0; }
        .prose h2 { font-size: 1.25em; }
        .prose ul { list-style-type: disc; padding-left: 1.5em; }
        .prose blockquote { border-left: 4px solid #e2e8f0; padding-left: 1em; color: #64748b; }
        .prose pre { background: #1e293b; color: #e2e8f0; padding: 1em; border-radius: 0.5em; overflow-x: auto; }
        .prose code { font-family: monospace; background: #f1f5f9; padding: 0.2em 0.4em; border-radius: 0.25em; font-size: 0.9em; }
        .prose a { color: #3b82f6; text-decoration: underline; }
    </style>
</head>
<body class="bg-[#f8fafc] text-slate-700 h-screen overflow-hidden selection:bg-blue-100 selection:text-blue-700">
    <div id="app" class="w-full flex h-full" @click="closeContextMenu" @contextmenu="closeContextMenu">
        
        <div v-if="!isLoggedIn" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900 overflow-hidden">
            <div class="absolute inset-0 overflow-hidden pointer-events-none">
                <div class="absolute top-[-20%] left-[-10%] w-[60%] h-[60%] bg-blue-600/30 rounded-full blur-[120px] animate-pulse"></div>
                <div class="absolute bottom-[-20%] right-[-10%] w-[60%] h-[60%] bg-violet-600/30 rounded-full blur-[120px]" style="animation-delay: 1s"></div>
            </div>
            <div class="bg-white/10 backdrop-blur-2xl w-full max-w-[360px] p-8 rounded-[32px] shadow-2xl border border-white/10 relative z-10 transition-all duration-300">
                <div class="text-center mb-10">
                    <div class="w-16 h-16 bg-gradient-to-tr from-blue-500 to-violet-600 rounded-2xl flex items-center justify-center mx-auto mb-6 shadow-lg shadow-blue-900/40 text-white text-2xl transform -rotate-6 border border-white/20">
                        <i class="fa-solid fa-cloud"></i>
                    </div>
                    <h1 class="text-2xl font-bold text-white tracking-tight mb-2">{{ !serverInitialized ? '系统初始化' : '欢迎回来' }}</h1>
                    <p class="text-slate-400 text-sm font-medium">{{ !serverInitialized ? '设置您的管理员账户' : '进入您的私有云空间' }}</p>
                </div>
                <form @submit.prevent="handleAuth" class="space-y-5">
                    <div class="space-y-4">
                        <div class="relative group">
                            <input v-model="authForm.username" type="text" placeholder="用户名" class="w-full px-5 py-3.5 bg-slate-800/50 border border-slate-700/50 rounded-xl outline-none focus:bg-slate-800 focus:border-blue-500/50 focus:ring-4 focus:ring-blue-500/10 transition-all text-sm font-medium text-white placeholder-slate-500" required>
                        </div>
                        <div class="relative group">
                            <input v-model="authForm.password" type="password" placeholder="密码" class="w-full px-5 py-3.5 bg-slate-800/50 border border-slate-700/50 rounded-xl outline-none focus:bg-slate-800 focus:border-blue-500/50 focus:ring-4 focus:ring-blue-500/10 transition-all text-sm font-medium text-white placeholder-slate-500" required>
                        </div>
                    </div>
                    <button class="w-full bg-white text-slate-900 hover:bg-slate-50 font-bold py-3.5 rounded-xl transition-all active:scale-[0.98] flex items-center justify-center gap-2 shadow-xl shadow-white/5">
                        <span>{{ !serverInitialized ? '完成设置' : '登录' }}</span>
                        <i class="fa-solid fa-arrow-right text-xs opacity-50"></i>
                    </button>
                </form>
            </div>
        </div>

        <template v-if="isLoggedIn">
            <div v-if="mobileMenuOpen" @click.stop="mobileMenuOpen = false" class="fixed inset-0 bg-black/60 z-30 md:hidden backdrop-blur-sm transition-all"></div>

            <aside :class="['glass-sidebar w-72 text-slate-300 flex flex-col flex-shrink-0 md:relative z-40 transition-transform duration-300 ease-out border-r border-white/5', mobileMenuOpen ? 'open fixed h-full translate-x-0' : 'fixed h-full -translate-x-full md:translate-x-0 md:static']" @click.stop>
                <div class="p-8 flex items-center gap-3">
                    <div class="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center text-white text-sm shadow-lg shadow-blue-500/20"><i class="fa-solid fa-cloud"></i></div>
                    <span class="text-lg font-bold text-white tracking-wide">文件管理</span>
                </div>
                
                <nav class="flex-1 px-3 space-y-1 overflow-y-auto scroll-visible pt-4">
                    <div class="text-xs font-bold text-slate-500 px-4 py-2 uppercase tracking-wider">Menu</div>
                    <div @click="switchView('uploads')" :class="['sidebar-item px-4 py-3 rounded-xl flex items-center gap-3 font-medium cursor-pointer', currentView === 'uploads' ? 'active' : 'hover:bg-white/5']">
                        <i class="fa-solid fa-cloud-arrow-up w-5 text-center"></i> 传输列表
                        <span v-if="activeUploadCount > 0" class="ml-auto bg-blue-500 text-white text-[10px] font-bold px-1.5 py-0.5 rounded-md shadow-lg shadow-blue-500/40 animate-pulse">{{ activeUploadCount }}</span>
                    </div>
                    <div @click="switchView('files')" :class="['sidebar-item px-4 py-3 rounded-xl flex items-center gap-3 font-medium cursor-pointer', currentView === 'files' ? 'active' : 'hover:bg-white/5']">
                        <i class="fa-regular fa-folder w-5 text-center"></i> 全部文件
                    </div>
                    <div @click="switchView('shares')" :class="['sidebar-item px-4 py-3 rounded-xl flex items-center gap-3 font-medium cursor-pointer', currentView === 'shares' ? 'active' : 'hover:bg-white/5']">
                        <i class="fa-solid fa-share-nodes w-5 text-center"></i> 我的分享
                    </div>
                    <div @click="switchView('trash')" :class="['sidebar-item px-4 py-3 rounded-xl flex items-center gap-3 font-medium cursor-pointer', currentView === 'trash' ? 'active' : 'hover:bg-white/5']">
                        <i class="fa-solid fa-trash-arrow-up w-5 text-center"></i> 回收站
                    </div>
                    
                    <div class="mt-6 text-xs font-bold text-slate-500 px-4 py-2 uppercase tracking-wider">System</div>
                    <div @click="switchView('settings')" :class="['sidebar-item px-4 py-3 rounded-xl flex items-center gap-3 font-medium cursor-pointer', currentView === 'settings' ? 'active' : 'hover:bg-white/5']">
                        <i class="fa-solid fa-gear w-5 text-center"></i> 系统设置
                    </div>
                </nav>

                <div class="p-4 border-t border-white/5">
                    <div class="bg-slate-800/50 rounded-xl p-3 flex items-center gap-3 border border-white/5">
                        <div class="w-8 h-8 rounded-full bg-gradient-to-br from-slate-600 to-slate-700 flex items-center justify-center text-xs text-white font-bold">U</div>
                        <div class="flex-1 min-w-0">
                            <div class="text-sm font-medium text-white truncate">管理员</div>
                            <div class="text-[10px] text-slate-400">Online</div>
                        </div>
                        <button @click="logout" class="text-slate-400 hover:text-white transition p-2"><i class="fa-solid fa-right-from-bracket"></i></button>
                    </div>
                </div>
            </aside>

            <main class="main-content flex-1 flex flex-col min-w-0 bg-[#f8fafc] md:ml-0 relative h-full">
                <div class="md:hidden bg-white/80 backdrop-blur-md p-4 flex items-center sticky top-0 z-20 border-b border-slate-100" @click.stop>
                    <button @click="mobileMenuOpen = true" class="text-slate-600 p-1"><i class="fa-solid fa-bars text-xl"></i></button>
                    <span class="ml-4 font-bold text-slate-700">我的文件</span>
                </div>

                <div class="flex-1 overflow-y-auto p-4 md:p-8 scroll-visible pb-32">
                    
                    <input type="file" ref="uploadInput" @change="e => handleFiles(e.target.files)" class="hidden" multiple>

                    <div v-if="currentView === 'uploads'" class="max-w-5xl mx-auto space-y-8 animate-fade-in" @click.stop>
                        <div>
                            <h2 class="text-2xl font-bold text-slate-800 mb-6 flex items-center gap-2"><i class="fa-solid fa-cloud-arrow-up text-blue-500"></i> 上传中心</h2>
                            
                            <div @dragover.prevent @drop.prevent="handleDrop" class="group border-2 border-dashed border-slate-300 rounded-3xl p-12 text-center bg-white hover:border-blue-400 hover:bg-blue-50/30 transition-all cursor-pointer mb-8 relative overflow-hidden" @click="$refs.uploadInput.click()">
                                <div class="absolute inset-0 bg-grid-slate-100 [mask-image:linear-gradient(0deg,white,rgba(255,255,255,0.6))] pointer-events-none"></div>
                                <div class="relative z-10 transition-transform group-hover:scale-105 duration-300">
                                    <div class="w-16 h-16 bg-blue-50 text-blue-500 rounded-2xl mx-auto flex items-center justify-center text-3xl mb-4 group-hover:shadow-lg group-hover:shadow-blue-200 transition-all"><i class="fa-solid fa-cloud-arrow-up"></i></div>
                                    <p class="text-slate-600 font-medium text-lg">点击上传文件，或拖拽文件/文件夹到此处</p>
                                    <p class="text-slate-400 text-sm mt-2">支持递归扫描文件夹，当前目录: <span class="font-mono text-blue-500 bg-blue-50 px-1.5 py-0.5 rounded">{{ currentPath || '根目录' }}</span></p>
                                </div>
                            </div>

                            <div v-if="uploadQueue.length > 0" class="space-y-3">
                                <div v-for="item in uploadQueue" :key="item.id" class="bg-white p-4 rounded-2xl border border-slate-100 shadow-sm flex items-center gap-4 transition-all hover:shadow-md">
                                    <div class="w-10 h-10 rounded-lg bg-slate-50 flex items-center justify-center text-blue-500 text-lg"><i class="fa-regular fa-file"></i></div>
                                    <div class="flex-1 min-w-0">
                                        <div class="flex justify-between mb-1.5">
                                            <div class="font-medium text-slate-700 truncate text-sm">{{ item.relativePath || item.file.name }}</div>
                                            <div class="text-xs font-bold" :class="{'text-blue-500': item.status==='uploading', 'text-green-500': item.status==='success', 'text-red-500': item.status==='error'}">{{ item.statusText }}</div>
                                        </div>
                                        <div class="w-full bg-slate-100 rounded-full h-1.5 overflow-hidden">
                                            <div class="bg-blue-500 h-1.5 rounded-full transition-all duration-300" :style="{ width: item.progress + '%' }"></div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div v-if="uploadHistory.length > 0">
                            <div class="flex justify-between items-center mb-4">
                                <h3 class="text-lg font-bold text-slate-700">历史记录</h3>
                                <div class="flex gap-2">
                                    <button @click="clearUploadHistory" class="text-red-400 hover:text-red-500 bg-red-50 px-3 py-1.5 rounded-lg text-sm transition font-medium flex items-center gap-2" title="清空历史记录">
                                        <i class="fa-solid fa-trash-can"></i> 清空
                                    </button>
                                    <button @click="fetchUploadHistory" class="text-slate-500 hover:text-blue-600 bg-white border px-3 py-1.5 rounded-lg text-sm transition flex items-center gap-2">
                                        <i class="fa-solid fa-rotate-right"></i> 刷新
                                    </button>
                                </div>
                            </div>
                            <div class="bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden">
                                <table class="w-full text-left text-sm">
                                    <thead class="bg-slate-50 text-slate-500 font-medium">
                                        <tr><th class="px-6 py-3">文件名</th><th class="px-6 py-3">大小</th><th class="px-6 py-3 text-right">时间</th></tr>
                                    </thead>
                                    <tbody class="divide-y divide-slate-100">
                                        <tr v-for="(log, idx) in uploadHistory" :key="idx" class="hover:bg-slate-50/50 transition">
                                            <td class="px-6 py-3.5 text-slate-700 truncate max-w-xs font-medium">{{ log.name }}</td>
                                            <td class="px-6 py-3.5 text-slate-500">{{ formatSize(log.size) }}</td>
                                            <td class="px-6 py-3.5 text-slate-400 text-right text-xs">{{ new Date(log.date).toLocaleString() }}</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                    <div v-if="currentView === 'files'" class="space-y-6 animate-fade-in">
                        <div class="glass-panel sticky top-0 z-10 p-3 rounded-2xl mb-6 shadow-sm" @click.stop>
                            <div class="flex flex-wrap justify-between items-center gap-4">
                                <div class="flex items-center text-sm text-slate-600 px-2 overflow-x-auto scroll-visible max-w-[60%]">
                                    <button @click="navigateTo('')" class="hover:bg-white hover:shadow-sm px-2 py-1 rounded-lg transition flex items-center gap-1.5 font-bold text-slate-800"><i class="fa-solid fa-house text-blue-500"></i> 首页</button>
                                    <template v-for="(part, index) in pathParts" :key="index">
                                        <span class="text-slate-300 mx-1">/</span>
                                        <button @click="navigateTo(part.fullPath)" class="hover:bg-white hover:shadow-sm px-2 py-1 rounded-lg transition font-medium whitespace-nowrap text-slate-600">{{ part.name }}</button>
                                    </template>
                                </div>

                                <div class="flex gap-2 items-center ml-auto">
                                    <template v-if="!isSelectionMode">
                                        <div class="relative group">
                                            <input v-model="searchQuery" type="text" placeholder="搜索文件..." class="pl-9 pr-4 py-2 bg-slate-100 border-none rounded-xl text-sm outline-none focus:bg-white focus:ring-2 focus:ring-blue-500/20 w-32 focus:w-56 transition-all placeholder-slate-400">
                                            <i class="fa-solid fa-magnifying-glass absolute left-3 top-2.5 text-slate-400 text-xs"></i>
                                        </div>
                                        <div class="h-6 w-px bg-slate-200 mx-1"></div>
                                        <div class="flex bg-slate-100 p-1 rounded-xl">
                                            <button @click="viewMode = 'list'" :class="['w-8 h-8 rounded-lg text-xs transition-all shadow-sm', viewMode==='list'?'bg-white text-blue-600 shadow':'text-slate-500 hover:text-slate-700']"><i class="fa-solid fa-list"></i></button>
                                            <button @click="viewMode = 'grid'" :class="['w-8 h-8 rounded-lg text-xs transition-all shadow-sm', viewMode==='grid'?'bg-white text-blue-600 shadow':'text-slate-500 hover:text-slate-700']"><i class="fa-solid fa-border-all"></i></button>
                                        </div>
                                        <button @click="createFolderModal.show = true" class="bg-slate-900 hover:bg-slate-800 text-white px-4 py-2 rounded-xl text-sm transition shadow-lg shadow-slate-300/50 flex items-center gap-2 active:scale-95">
                                            <i class="fa-solid fa-folder-plus"></i> <span class="hidden sm:inline">新建</span>
                                        </button>
                                    </template>
                                    <template v-else>
                                        <button @click="selectAll" class="bg-white border text-slate-600 hover:bg-slate-50 px-3 py-2 rounded-xl text-sm transition">全选</button>
                                        <button @click="invertSelection" class="bg-white border text-slate-600 hover:bg-slate-50 px-3 py-2 rounded-xl text-sm transition">反选</button>
                                    </template>
                                    <button @click="toggleSelectionMode" :class="['w-9 h-9 flex items-center justify-center rounded-xl text-sm transition ml-1', isSelectionMode ? 'bg-blue-500 text-white shadow-lg shadow-blue-500/30' : 'bg-white border text-slate-500 hover:text-blue-500']">
                                        <i class="fa-solid fa-check-double"></i>
                                    </button>
                                </div>
                            </div>
                        </div>

                        <div v-if="viewMode === 'list'" class="bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden min-h-[400px]">
                            <table class="w-full text-left">
                                <thead class="bg-slate-50/50 border-b border-slate-100 text-slate-400 text-xs uppercase tracking-wider font-medium">
                                    <tr>
                                        <th v-if="isSelectionMode" class="w-14 py-3 text-center"><div class="checkbox-wrapper"><input type="checkbox" :checked="isAllSelected" @change="toggleSelectAll"></div></th>
                                        <th class="px-5 py-3 font-medium">名称</th>
                                        <th class="px-5 py-3 font-medium w-32">大小</th>
                                        <th class="px-5 py-3 font-medium w-40 text-right">修改时间</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-slate-50 text-sm">
                                    <tr v-if="sortedFiles.length === 0"><td colspan="4" class="px-6 py-20 text-center text-slate-400"><div class="text-4xl mb-3 text-slate-200"><i class="fa-regular fa-folder-open"></i></div>无文件</td></tr>
                                    <tr v-for="file in sortedFiles" :key="file.key" class="group hover:bg-blue-50/50 transition duration-150 cursor-default select-none relative" :class="{'bg-blue-50/80': selectedFiles.includes(file.key)}" @contextmenu.prevent.stop="showContextMenu($event, file)" @click="handleRowClick(file)">
                                        <td v-if="isSelectionMode" class="w-14 py-4 text-center relative z-10" @click.stop><div class="checkbox-wrapper"><input type="checkbox" :value="file.key" v-model="selectedFiles"></div></td>
                                        <td class="px-5 py-3.5">
                                            <div class="flex items-center gap-4">
                                                <div class="w-9 h-9 rounded-lg flex items-center justify-center text-lg transition-transform group-hover:scale-110 shadow-sm" :class="file.isFolder ? 'bg-yellow-100 text-yellow-500' : 'bg-slate-100 text-slate-500'">
                                                    <i :class="getFileIcon(file)"></i>
                                                </div>
                                                <span class="truncate font-medium text-slate-700 group-hover:text-blue-600 transition-colors">{{ getDisplayName(file.key) }}</span>
                                            </div>
                                        </td>
                                        <td class="px-5 py-3.5 text-slate-500 font-mono text-xs">{{ file.isFolder ? '-' : formatSize(file.size) }}</td>
                                        <td class="px-5 py-3.5 text-right text-slate-400 text-xs">{{ file.uploaded ? new Date(file.uploaded).toLocaleDateString() : '-' }}</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>

                        <div v-if="viewMode === 'grid'" class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 xl:grid-cols-8 gap-4 min-h-[400px] content-start">
                            <div v-for="file in sortedFiles" :key="file.key" 
                                class="folder-grid-item bg-white rounded-2xl p-4 flex flex-col items-center gap-3 cursor-pointer relative group border border-slate-100"
                                :class="{'ring-2 ring-blue-500 shadow-md bg-blue-50/30': selectedFiles.includes(file.key)}"
                                @click="handleRowClick(file)"
                                @contextmenu.prevent.stop="showContextMenu($event, file)"
                            >
                                <div v-if="isSelectionMode" class="absolute top-2 right-2 z-10" @click.stop>
                                    <div class="checkbox-wrapper"><input type="checkbox" :value="file.key" v-model="selectedFiles"></div>
                                </div>
                                <div class="w-14 h-14 rounded-2xl flex items-center justify-center text-3xl shadow-sm transition-transform group-hover:scale-110 duration-300" :class="file.isFolder ? 'bg-gradient-to-br from-yellow-100 to-yellow-50 text-yellow-500' : 'bg-slate-50 text-slate-400'">
                                    <i :class="getFileIcon(file)"></i>
                                </div>
                                <div class="text-center w-full">
                                    <div class="text-xs text-slate-700 font-medium truncate w-full px-1 group-hover:text-blue-600 transition-colors">{{ getDisplayName(file.key) }}</div>
                                    <div class="text-[10px] text-slate-400 mt-0.5 font-mono">{{ file.isFolder ? 'Folder' : formatSize(file.size) }}</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div v-if="currentView === 'trash'" class="space-y-6 animate-fade-in" @click.stop>
                        <div class="flex justify-between items-center gap-4">
                            <h2 class="text-2xl font-bold text-slate-800 flex items-center gap-2"><i class="fa-solid fa-trash-arrow-up text-red-500"></i> 回收站</h2>
                             <div v-if="selectedTrash.length > 0" class="flex gap-2">
                                <button @click="restoreTrash" class="bg-green-500 text-white px-3 py-1.5 rounded-lg text-sm shadow-md hover:bg-green-600 transition"><i class="fa-solid fa-rotate-left"></i> 还原</button>
                                <button @click="deleteTrashForever" class="bg-red-500 text-white px-3 py-1.5 rounded-lg text-sm shadow-md hover:bg-red-600 transition"><i class="fa-solid fa-ban"></i> 彻底删除</button>
                            </div>
                        </div>
                        <div class="bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden">
                            <table class="w-full text-left text-sm">
                                <thead class="bg-slate-50/50 border-b border-slate-100 text-slate-400 text-xs font-medium uppercase">
                                    <tr>
                                        <th class="w-12 py-3 text-center"><div class="checkbox-wrapper"><input type="checkbox" @change="e => selectedTrash = e.target.checked ? trashFiles.map(t => t.key) : []" :checked="trashFiles.length > 0 && selectedTrash.length === trashFiles.length"></div></th>
                                        <th class="px-6 py-3">原路径</th>
                                        <th class="px-6 py-3">大小</th>
                                        <th class="px-6 py-3 text-right">删除时间</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-slate-50">
                                    <tr v-for="item in trashFiles" :key="item.key" class="hover:bg-red-50/30 transition">
                                         <td class="w-12 py-4 text-center"><div class="checkbox-wrapper"><input type="checkbox" :value="item.key" v-model="selectedTrash"></div></td>
                                        <td class="px-6 py-4 truncate max-w-xs text-slate-700 font-medium">{{ item.originalPath }}</td>
                                        <td class="px-6 py-4 text-slate-500 font-mono text-xs">{{ formatSize(item.size) }}</td>
                                        <td class="px-6 py-4 text-right text-slate-400 text-xs">{{ new Date(item.deletedAt).toLocaleString() }}</td>
                                    </tr>
                                </tbody>
                            </table>
                            <div v-if="trashFiles.length === 0" class="p-8 text-center text-slate-400">回收站是空的</div>
                        </div>
                    </div>

                    <div v-if="currentView === 'shares'" class="space-y-6 animate-fade-in" @click.stop>
                         <div class="flex flex-wrap justify-between items-center gap-4">
                            <h2 class="text-2xl font-bold text-slate-800 flex items-center gap-2"><i class="fa-solid fa-share-nodes text-green-500"></i> 分享管理</h2>
                            <div class="flex gap-2 items-center">
                                <template v-if="isShareSelectionMode">
                                    <button @click="selectAllShares" class="bg-white border text-slate-600 hover:bg-slate-50 px-3 py-2 rounded-xl text-sm transition">全选</button>
                                    <button @click="invertShareSelection" class="bg-white border text-slate-600 hover:bg-slate-50 px-3 py-2 rounded-xl text-sm transition">反选</button>
                                </template>
                                <button @click="toggleShareSelectionMode" :class="['px-3 py-2 rounded-xl text-sm transition flex items-center gap-2 font-medium', isShareSelectionMode ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/30' : 'bg-white border text-slate-600 hover:bg-slate-50']">
                                    <i class="fa-solid fa-check-double"></i> 管理
                                </button>
                                <button v-if="!isShareSelectionMode" @click="fetchShares" class="p-2 text-slate-400 hover:text-blue-500 transition"><i class="fa-solid fa-rotate-right"></i></button>
                            </div>
                        </div>
                        <div class="bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden">
                             <table class="w-full text-left text-sm">
                                <thead class="bg-slate-50/50 border-b border-slate-100 text-slate-400 text-xs font-medium uppercase">
                                    <tr>
                                        <th v-if="isShareSelectionMode" class="w-12 py-3 text-center"><div class="checkbox-wrapper"><input type="checkbox" :checked="isAllSharesSelected" @change="e => selectedShares = e.target.checked ? shares.map(s => s.token) : []"></div></th>
                                        <th class="px-6 py-3">文件</th>
                                        <th class="px-6 py-3">Token</th>
                                        <th class="px-6 py-3 text-center">访问量</th>
                                        <th class="px-6 py-3 text-right">状态</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-slate-50">
                                    <tr v-for="item in shares" :key="item.token" class="hover:bg-blue-50/50 transition cursor-default" :class="{'bg-blue-50/50': selectedShares.includes(item.token)}" @click="isShareSelectionMode ? toggleShareSelection(item.token) : null" @contextmenu.prevent.stop="showContextMenu($event, item, 'share')">
                                        <td v-if="isShareSelectionMode" class="w-12 py-4 text-center" @click.stop><div class="checkbox-wrapper"><input type="checkbox" :value="item.token" v-model="selectedShares"></div></td>
                                        <td class="px-6 py-4 truncate max-w-xs font-medium text-slate-700" :title="item.path">{{ item.path }}</td>
                                        <td class="px-6 py-4 text-slate-500 font-mono text-xs select-all">{{ item.token }}</td>
                                        <td class="px-6 py-4 text-center"><span class="bg-slate-100 text-slate-600 px-2 py-0.5 rounded text-xs font-bold">{{ item.views }}</span> <span v-if="item.maxViews" class="text-slate-400 text-xs">/ {{ item.maxViews }}</span></td>
                                        <td class="px-6 py-4 text-right">
                                            <div class="flex flex-col gap-1 items-end">
                                                <span v-if="item.password" class="text-[10px] border border-yellow-200 bg-yellow-50 text-yellow-600 px-1.5 rounded"><i class="fa-solid fa-lock"></i> 加密</span>
                                                <span v-if="item.expireTime" :class="['text-[10px] border px-1.5 rounded', new Date(item.expireTime) < new Date() ? 'bg-red-50 text-red-500 border-red-100' : 'bg-green-50 text-green-600 border-green-100']">{{ new Date(item.expireTime) < new Date() ? '已过期' : '有效期内' }}</span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div v-if="currentView === 'settings'" class="max-w-2xl mx-auto animate-fade-in" @click.stop>
                        <h2 class="text-2xl font-bold text-slate-800 mb-6 flex items-center gap-2"><i class="fa-solid fa-gear text-slate-400"></i> 系统设置</h2>
                        <div class="bg-white p-8 rounded-3xl shadow-sm border border-slate-100 space-y-6">
                            
                            <div class="grid grid-cols-2 gap-4 mb-2">
                                <div class="bg-blue-50 rounded-2xl p-5 border border-blue-100">
                                    <div class="text-blue-400 text-xs font-bold uppercase mb-2">已用空间</div>
                                    <div class="text-2xl font-bold text-slate-700">{{ stats.sizeStr || '计算中...' }}</div>
                                    <div class="text-slate-400 text-xs mt-1">云端存储</div>
                                </div>
                                <div class="bg-violet-50 rounded-2xl p-5 border border-violet-100">
                                    <div class="text-violet-400 text-xs font-bold uppercase mb-2">文件数量</div>
                                    <div class="text-2xl font-bold text-slate-700">{{ stats.count || '-' }}</div>
                                    <div class="text-slate-400 text-xs mt-1">个对象</div>
                                </div>
                            </div>

                            <div>
                                <h3 class="font-bold text-slate-700 mb-2">修改管理员密码</h3>
                                <p class="text-slate-400 text-sm mb-4">为了安全起见，建议定期更换高强度密码。</p>
                                <div class="flex gap-4">
                                    <input v-model="newPassword" type="password" placeholder="输入新密码" class="flex-1 bg-slate-50 border border-slate-200 rounded-xl px-5 py-3 outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all">
                                    <button @click="updatePassword" class="bg-slate-900 text-white px-6 py-3 rounded-xl hover:bg-slate-800 shadow-lg shadow-slate-200 transition active:scale-95 font-medium">保存修改</button>
                                </div>
                            </div>
                            <div class="border-t border-slate-100 pt-6">
                                <h3 class="font-bold text-slate-700 mb-2">关于系统</h3>
                                <div class="bg-blue-50 rounded-xl p-4 flex items-start gap-4">
                                    <div class="text-blue-500 text-xl"><i class="fa-solid fa-circle-info"></i></div>
                                    <div>
                                        <p class="text-slate-700 font-medium text-sm">Cloudflare Worker Manager</p>
                                        <p class="text-slate-500 text-xs mt-1">版本: v3.1.0 (Clean) / 运行区域: {{ env && env.CF_PAGES_URL ? 'Pages' : 'Workers' }}</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <transition name="slide-up">
                    <div v-if="selectedFiles.length > 0 && currentView === 'files'" class="absolute bottom-8 left-0 right-0 flex justify-center z-20 pointer-events-none">
                        <div class="bg-slate-900/90 backdrop-blur-md text-white rounded-2xl p-2 pr-6 shadow-2xl shadow-slate-900/30 flex items-center gap-4 pointer-events-auto border border-white/10">
                            <div class="bg-slate-800 rounded-xl px-4 py-2 text-sm font-bold text-white flex items-center gap-2">
                                <span class="w-5 h-5 bg-blue-500 rounded-full flex items-center justify-center text-[10px]">{{ selectedFiles.length }}</span>
                                已选
                            </div>
                            <div class="h-6 w-px bg-white/10"></div>
                            <button @click="openMoveModal" class="text-slate-300 hover:text-white font-medium text-sm flex items-center gap-2 transition hover:bg-white/10 px-3 py-1.5 rounded-lg"><i class="fa-solid fa-arrow-right-to-bracket"></i> 移动</button>
                            <button @click="batchDelete" class="text-red-400 hover:text-red-300 font-medium text-sm flex items-center gap-2 transition hover:bg-red-500/10 px-3 py-1.5 rounded-lg"><i class="fa-solid fa-trash-can"></i> 删除</button>
                            <button @click="selectedFiles = []" class="ml-2 w-8 h-8 rounded-full hover:bg-white/20 flex items-center justify-center text-slate-400 hover:text-white transition"><i class="fa-solid fa-xmark"></i></button>
                        </div>
                    </div>
                </transition>
                
                <transition name="slide-up">
                    <div v-if="selectedShares.length > 0 && currentView === 'shares'" class="absolute bottom-8 left-0 right-0 flex justify-center z-20 pointer-events-none">
                        <div class="bg-slate-900/90 backdrop-blur-md text-white rounded-2xl p-2 pr-6 shadow-2xl shadow-slate-900/30 flex items-center gap-4 pointer-events-auto border border-white/10">
                             <div class="bg-slate-800 rounded-xl px-4 py-2 text-sm font-bold text-white flex items-center gap-2">
                                <span class="w-5 h-5 bg-blue-500 rounded-full flex items-center justify-center text-[10px]">{{ selectedShares.length }}</span>
                                选中
                            </div>
                            <div class="h-6 w-px bg-white/10"></div>
                            <button @click="batchCopyLinks" class="text-blue-400 hover:text-blue-300 font-medium text-sm flex items-center gap-2 transition hover:bg-blue-500/10 px-3 py-1.5 rounded-lg"><i class="fa-solid fa-copy"></i> 复制链接</button>
                            <button @click="batchDeleteShares" class="text-red-400 hover:text-red-300 font-medium text-sm flex items-center gap-2 transition hover:bg-red-500/10 px-3 py-1.5 rounded-lg"><i class="fa-solid fa-trash-can"></i> 撤销</button>
                            <button @click="selectedShares = []" class="ml-2 w-8 h-8 rounded-full hover:bg-white/20 flex items-center justify-center text-slate-400 hover:text-white transition"><i class="fa-solid fa-xmark"></i></button>
                        </div>
                    </div>
                </transition>
            </main>

            <transition name="modal">
                <div v-if="lightbox.show" class="fixed inset-0 z-[3000] bg-slate-900/95 backdrop-blur-md flex flex-col items-center justify-center" @click="lightbox.show = false">
                    <button class="absolute top-6 right-6 w-10 h-10 rounded-full bg-white/10 hover:bg-white/20 text-white flex items-center justify-center transition"><i class="fa-solid fa-xmark"></i></button>
                    <img v-if="lightbox.type === 'image'" :src="lightbox.url" class="max-w-[90%] max-h-[85vh] object-contain shadow-2xl rounded-lg animate-menuScale" @click.stop>
                    <video v-if="lightbox.type === 'video'" :src="lightbox.url" controls autoplay class="max-w-[90%] max-h-[85vh] shadow-2xl rounded-lg" @click.stop></video>
                    <div class="mt-6 text-white/80 font-medium text-sm px-4 py-2 bg-black/50 rounded-full backdrop-blur">{{ lightbox.name }}</div>
                </div>
            </transition>

            <transition name="modal">
                <div v-if="editor.show" class="fixed inset-0 z-[2500] flex items-center justify-center bg-slate-900/40 backdrop-blur-sm p-4" @click.self="editor.show = false">
                    <div class="bg-white rounded-2xl shadow-2xl w-full max-w-4xl h-[85vh] flex flex-col overflow-hidden ring-1 ring-black/5">
                        <div class="flex justify-between items-center px-6 py-4 border-b border-slate-100 bg-slate-50/50">
                            <h3 class="font-bold text-slate-700 flex items-center gap-2"><i class="fa-solid fa-code text-blue-500"></i> {{ editor.filename }}</h3>
                            <div class="flex gap-3">
                                <button v-if="editor.filename.endsWith('.md')" @click="editor.previewMode = !editor.previewMode" class="px-3 py-2 text-slate-600 bg-white border border-slate-200 hover:bg-slate-50 rounded-lg text-sm transition">
                                    <i :class="editor.previewMode ? 'fa-solid fa-eye-slash' : 'fa-solid fa-eye'"></i> {{ editor.previewMode ? '编辑' : '预览' }}
                                </button>
                                <button @click="editor.show = false" class="px-4 py-2 text-slate-500 hover:bg-slate-100 rounded-lg text-sm font-medium transition">关闭</button>
                                <button @click="saveTextContent" :disabled="editor.saving" class="px-5 py-2 bg-slate-900 text-white hover:bg-slate-800 rounded-lg text-sm font-medium flex items-center gap-2 shadow-lg shadow-slate-200 transition active:scale-95">
                                    <i v-if="editor.saving" class="fa-solid fa-spinner fa-spin"></i>
                                    <i v-else class="fa-solid fa-floppy-disk"></i> 保存
                                </button>
                            </div>
                        </div>
                        <div class="flex-1 relative overflow-hidden">
                            <textarea v-show="!editor.previewMode" v-model="editor.content" class="w-full h-full p-6 font-mono text-sm resize-none outline-none focus:bg-blue-50/10 transition leading-relaxed text-slate-700" spellcheck="false" @keydown.ctrl.s.prevent="saveTextContent"></textarea>
                            <div v-show="editor.previewMode" class="w-full h-full p-6 overflow-y-auto prose prose-slate max-w-none bg-white" v-html="compiledMarkdown"></div>
                        </div>
                    </div>
                </div>
            </transition>

            <div v-if="contextMenu.visible" :style="{ top: contextMenu.y + 'px', left: contextMenu.x + 'px' }" class="context-menu" @click.stop @contextmenu.prevent>
                 <template v-if="contextMenu.type === 'share'">
                    <div class="px-4 py-2.5 bg-slate-50 text-xs font-bold text-slate-400 border-b border-slate-100">分享操作</div>
                    <div class="context-menu-item" @click="handleMenuAction('openShare')"><i class="fa-solid fa-up-right-from-square text-slate-400"></i> 打开链接</div>
                    <div class="context-menu-item" @click="handleMenuAction('copyShare')"><i class="fa-solid fa-copy text-blue-500"></i> 复制链接</div>
                    <div class="h-px bg-slate-100 my-1"></div>
                    <div class="context-menu-item text-red-600 hover:bg-red-50" @click="handleMenuAction('deleteShare')"><i class="fa-solid fa-trash-can"></i> 撤销分享</div>
                </template>
                <template v-else-if="contextMenu.type === 'batch-share'">
                    <div class="px-4 py-2.5 bg-blue-50/50 text-xs font-bold text-blue-600 border-b border-blue-100">选中 {{ selectedShares.length }} 项</div>
                    <div class="context-menu-item" @click="batchCopyLinks"><i class="fa-solid fa-copy text-blue-500"></i> 批量复制</div>
                    <div class="context-menu-item text-red-600 hover:bg-red-50" @click="batchDeleteShares"><i class="fa-solid fa-trash-can"></i> 批量撤销</div>
                     <div class="h-px bg-slate-100 my-1"></div>
                    <div class="context-menu-item" @click="selectedShares = []; contextMenu.visible = false"><i class="fa-solid fa-xmark text-slate-400"></i> 取消选择</div>
                </template>
                <template v-else>
                    <template v-if="contextMenu.type === 'single'">
                        <div class="px-4 py-2.5 bg-slate-50 text-xs font-bold text-slate-400 border-b border-slate-100 truncate max-w-[180px]">{{ getDisplayName(contextMenu.file.key) }}</div>
                        <div v-if="isTextFile(contextMenu.file.key)" class="context-menu-item" @click="handleMenuAction('edit')"><i class="fa-solid fa-pen-to-square text-orange-500"></i> 编辑文本</div>
                        <div v-if="!contextMenu.file.isFolder && !isTextFile(contextMenu.file.key)" class="context-menu-item" @click="handleMenuAction('preview')"><i class="fa-solid fa-eye text-blue-500"></i> 预览</div>
                        <div v-if="!contextMenu.file.isFolder" class="context-menu-item" @click="handleMenuAction('download')"><i class="fa-solid fa-download text-slate-500"></i> 下载</div>
                        <div v-if="!contextMenu.file.isFolder" class="context-menu-item" @click="handleMenuAction('rename')"><i class="fa-solid fa-pen text-slate-500"></i> 重命名</div>
                        <div class="context-menu-item" @click="openMoveModal(); contextMenu.visible = false; if(!selectedFiles.includes(contextMenu.file.key)) selectedFiles=[contextMenu.file.key]"><i class="fa-solid fa-arrow-right-to-bracket text-slate-500"></i> 移动</div>
                        <div v-if="!contextMenu.file.isFolder" class="context-menu-item" @click="handleMenuAction('share')"><i class="fa-solid fa-share-nodes text-green-500"></i> 分享</div>
                        <div class="h-px bg-slate-100 my-1"></div>
                        <div class="context-menu-item text-red-500 hover:bg-red-50" @click="handleMenuAction('delete')"><i class="fa-solid fa-trash-can"></i> 删除</div>
                    </template>
                    <template v-else>
                        <div class="px-4 py-2.5 bg-blue-50/50 text-xs font-bold text-blue-600 border-b border-blue-100">已选 {{ selectedFiles.length }} 项</div>
                        <div class="context-menu-item" @click="openMoveModal(); contextMenu.visible = false"><i class="fa-solid fa-arrow-right-to-bracket text-slate-500"></i> 批量移动</div>
                        <div class="context-menu-item text-red-500 hover:bg-red-50" @click="batchDelete"><i class="fa-solid fa-trash-can"></i> 批量删除</div>
                        <div class="h-px bg-slate-100 my-1"></div>
                        <div class="context-menu-item" @click="selectedFiles = []; contextMenu.visible = false"><i class="fa-solid fa-xmark text-slate-400"></i> 取消选择</div>
                    </template>
                </template>
            </div>

            <transition name="modal"><div v-if="shareConfigModal.show" class="fixed inset-0 z-[2000] flex items-center justify-center bg-slate-900/40 backdrop-blur-sm p-4" @click.self="shareConfigModal.show = false"><div class="bg-white rounded-2xl shadow-2xl p-6 w-full max-w-sm modal-content"><h3 class="text-lg font-bold text-slate-800 mb-4">创建分享</h3><p class="text-xs text-slate-500 mb-4 bg-slate-50 p-2 rounded border border-slate-100 break-all font-mono">{{ shareConfigModal.path }}</p><div class="space-y-4"><div><label class="text-xs text-slate-500 font-bold uppercase mb-1 block">访问密码</label><input v-model="shareConfigModal.password" type="text" placeholder="可选" class="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none text-sm"></div><div class="grid grid-cols-2 gap-4"><div><label class="text-xs text-slate-500 font-bold uppercase mb-1 block">有效期</label><select v-model="shareConfigModal.expireHours" class="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm outline-none"><option value="">永久</option><option value="24">24小时</option><option value="168">7天</option><option value="720">30天</option></select></div><div><label class="text-xs text-slate-500 font-bold uppercase mb-1 block">次数限制</label><input v-model="shareConfigModal.maxViews" type="number" placeholder="不限" class="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm outline-none"></div></div></div><div class="flex justify-end gap-3 mt-6"><button @click="shareConfigModal.show = false" class="px-5 py-2.5 rounded-xl text-slate-500 hover:bg-slate-50 text-sm font-medium">取消</button><button @click="confirmCreateShare" class="px-5 py-2.5 rounded-xl bg-green-500 text-white hover:bg-green-600 shadow-lg shadow-green-200 text-sm font-medium">创建链接</button></div></div></div></transition>
            
            <transition name="modal"><div v-if="createFolderModal.show" class="fixed inset-0 z-[2000] flex items-center justify-center bg-slate-900/40 backdrop-blur-sm p-4" @click.self="createFolderModal.show = false"><div class="bg-white rounded-2xl shadow-2xl p-6 w-full max-w-xs modal-content"><h3 class="text-lg font-bold text-slate-800 mb-4">新建文件夹</h3><input v-model="createFolderModal.name" type="text" placeholder="输入名称" class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none mb-6 text-sm" @keyup.enter="createFolder" autofocus><div class="flex justify-end gap-3"><button @click="createFolderModal.show = false" class="px-4 py-2 rounded-xl text-slate-500 hover:bg-slate-50 text-sm font-medium">取消</button><button @click="createFolder" class="px-4 py-2 rounded-xl bg-slate-900 text-white hover:bg-slate-800 shadow-lg shadow-slate-200 text-sm font-medium">创建</button></div></div></div></transition>
            
            <transition name="modal"><div v-if="moveModal.show" class="fixed inset-0 z-[2000] flex items-center justify-center bg-slate-900/40 backdrop-blur-sm p-4" @click.self="moveModal.show = false"><div class="bg-white rounded-2xl shadow-2xl p-6 w-full max-w-sm modal-content flex flex-col max-h-[70vh]"><h3 class="text-lg font-bold text-slate-800 mb-4 flex-shrink-0">移动到...</h3><div class="mb-4 flex-shrink-0"><input v-model="moveModal.target" type="text" placeholder="目标路径 (如: photos/)" class="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none text-sm"></div><div class="flex-1 overflow-y-auto scroll-visible border border-slate-100 rounded-xl bg-slate-50 p-2 mb-4"><div class="text-xs text-slate-400 mb-2 px-2 font-bold uppercase">文件夹列表</div><div @click="moveModal.target = ''" class="flex items-center gap-2 px-3 py-2 hover:bg-white hover:shadow-sm rounded-lg cursor-pointer text-sm transition" :class="{'text-blue-600 font-bold': moveModal.target === ''}"><i class="fa-solid fa-server text-slate-400"></i> 根目录</div><div v-for="f in moveModal.folderList" :key="f" @click="moveModal.target = f" class="flex items-center gap-2 px-3 py-2 hover:bg-white hover:shadow-sm rounded-lg cursor-pointer text-sm transition" :class="{'text-blue-600 font-bold': moveModal.target === f}"><i class="fa-regular fa-folder text-yellow-500"></i> {{ f }}</div></div><div class="flex justify-end gap-3 flex-shrink-0"><button @click="moveModal.show = false" class="px-4 py-2 rounded-xl text-slate-500 hover:bg-slate-50 text-sm font-medium">取消</button><button @click="confirmMove" class="px-4 py-2 rounded-xl bg-blue-600 text-white hover:bg-blue-700 shadow-lg shadow-blue-200 text-sm font-medium">移动</button></div></div></div></transition>
            
            <transition name="modal"><div v-if="renameModal.show" class="fixed inset-0 z-[2000] flex items-center justify-center bg-slate-900/40 backdrop-blur-sm p-4" @click.self="renameModal.show = false"><div class="bg-white rounded-2xl shadow-2xl p-6 w-full max-w-xs modal-content"><h3 class="text-lg font-bold text-slate-800 mb-4">重命名</h3><input v-model="renameModal.newKey" type="text" class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 outline-none mb-6 text-sm" @keyup.enter="confirmRename"><div class="flex justify-end gap-3"><button @click="renameModal.show = false" class="px-4 py-2 rounded-xl text-slate-500 hover:bg-slate-50 text-sm font-medium">取消</button><button @click="confirmRename" class="px-4 py-2 rounded-xl bg-slate-900 text-white hover:bg-slate-800 text-sm font-medium">保存</button></div></div></div></transition>
            
            <transition name="modal"><div v-if="deleteModal.show" class="fixed inset-0 z-[2000] flex items-center justify-center bg-slate-900/40 backdrop-blur-sm p-4" @click.self="deleteModal.show = false"><div class="bg-white rounded-2xl shadow-2xl p-6 w-full max-w-xs modal-content text-center"><div class="w-14 h-14 bg-red-50 text-red-500 rounded-full flex items-center justify-center mx-auto mb-4 text-2xl"><i class="fa-solid fa-triangle-exclamation"></i></div><h3 class="text-lg font-bold text-slate-800 mb-2">确认删除?</h3><p class="text-slate-500 mb-6 text-sm">此操作将文件移动到回收站。</p><div class="flex gap-3"><button @click="deleteModal.show = false" class="flex-1 py-2.5 rounded-xl text-slate-600 bg-slate-100 hover:bg-slate-200 text-sm font-medium transition">取消</button><button @click="confirmDelete" class="flex-1 py-2.5 rounded-xl bg-red-500 text-white hover:bg-red-600 shadow-lg shadow-red-200 text-sm font-medium transition">删除</button></div></div></div></transition>
        </template>
        
        <transition name="slide-up">
            <div v-if="toast.show" class="fixed top-6 left-1/2 transform -translate-x-1/2 bg-slate-800/90 backdrop-blur text-white px-6 py-3 rounded-full shadow-2xl text-sm font-medium z-[5000] flex items-center gap-3 ring-1 ring-white/10">
                <i class="fa-solid fa-circle-check text-green-400"></i> {{ toast.msg }}
            </div>
        </transition>
    </div>

    <script>
        const { createApp, ref, onMounted, computed, watch } = Vue;

        createApp({
            setup() {
                const serverInitialized = ref(${isInitialized});
                const isLoggedIn = ref(false);
                const mobileMenuOpen = ref(false);
                const currentView = ref(localStorage.getItem('fm_current_view') || 'uploads');
                
                const files = ref([]); const shares = ref([]); const uploadHistory = ref([]); const uploadQueue = ref([]); const selectedFiles = ref([]); const currentPath = ref('');
                const selectedShares = ref([]); const isShareSelectionMode = ref(false);
                const trashFiles = ref([]); const selectedTrash = ref([]);
                const stats = ref({ sizeStr: '', count: 0 });

                const authForm = ref({ username: '', password: '' }); const newPassword = ref(''); const toast = ref({ show: false, msg: '' });
                const contextMenu = ref({ visible: false, x: 0, y: 0, file: null, type: 'single' });
                const renameModal = ref({ show: false, oldKey: '', newKey: '' }); const deleteModal = ref({ show: false, key: '' }); const createFolderModal = ref({ show: false, name: '' }); const moveModal = ref({ show: false, target: '', folderList: [] }); const shareConfigModal = ref({ show: false, path: '', password: '', expireHours: '', maxViews: '' });
                const lightbox = ref({ show: false, url: '', type: '', name: '' });
                const editor = ref({ show: false, filename: '', content: '', key: '', saving: false, previewMode: false });
                const isUploading = ref(false);
                const searchQuery = ref('');
                const viewMode = ref(localStorage.getItem('fm_view_mode') || 'list');
                const isSelectionMode = ref(false);
                
                const savedSort = localStorage.getItem('fm_sort_option');
                const sortOption = ref(savedSort ? JSON.parse(savedSort) : { field: 'uploaded', order: 'desc' });

                onMounted(() => {
                    if (document.cookie.includes('${SESSION_KEY}')) { 
                        isLoggedIn.value = true; 
                        if(currentView.value==='uploads') fetchUploadHistory(); 
                        else if(currentView.value==='files') refreshFiles();
                        else if(currentView.value==='trash') fetchTrash();
                    }
                    window.addEventListener('click', closeContextMenu); window.addEventListener('contextmenu', (e) => { if(!e.target.closest('tr') && !e.target.closest('.folder-grid-item')) closeContextMenu(); });
                });

                watch(viewMode, (v) => localStorage.setItem('fm_view_mode', v));
                watch(sortOption, (v) => localStorage.setItem('fm_sort_option', JSON.stringify(v)), { deep: true });
                watch(currentView, (v) => localStorage.setItem('fm_current_view', v));

                const switchView = (view) => {
                    currentView.value = view; mobileMenuOpen.value = false; closeContextMenu(); 
                    if(view === 'files') { refreshFiles(); selectedFiles.value = []; isSelectionMode.value = false; } 
                    if(view === 'shares') { fetchShares(); selectedShares.value = []; isShareSelectionMode.value = false; }
                    if(view === 'uploads') fetchUploadHistory();
                    if(view === 'trash') { fetchTrash(); selectedTrash.value = []; }
                    if(view === 'settings') fetchStats();
                };

                const toggleSelectionMode = () => {
                    isSelectionMode.value = !isSelectionMode.value;
                    if (!isSelectionMode.value) selectedFiles.value = [];
                };

                const toggleShareSelectionMode = () => {
                    isShareSelectionMode.value = !isShareSelectionMode.value;
                    if (!isShareSelectionMode.value) selectedShares.value = [];
                };

                const refreshFiles = async () => { const res = await fetch('/api/files?prefix=' + encodeURIComponent(currentPath.value)); if(res.ok) files.value = await res.json(); };
                const fetchTrash = async () => { const res = await fetch('/api/trash/list'); if(res.ok) trashFiles.value = await res.json(); };
                const fetchStats = async () => { 
                    const res = await fetch('/api/stats'); 
                    if(res.ok) {
                        const d = await res.json();
                        stats.value = { sizeStr: formatSize(d.totalSize), count: d.count };
                    }
                };

                const navigateTo = (path) => { currentPath.value = path; selectedFiles.value = []; searchQuery.value = ''; isSelectionMode.value = false; refreshFiles(); };
                
                const handleRowClick = (file) => { 
                    if (isSelectionMode.value) {
                        toggleSelection(file.key);
                    } else {
                        if (file.isFolder) navigateTo(file.key); 
                        else {
                            const ext = file.key.split('.').pop().toLowerCase();
                            if (['jpg','png','jpeg','gif','webp','mp4','webm'].includes(ext)) openLightbox(file);
                        }
                    }
                };
                
                const openLightbox = (file) => {
                    const ext = file.key.split('.').pop().toLowerCase();
                    const type = ['mp4','webm'].includes(ext) ? 'video' : 'image';
                    lightbox.value = { show: true, url: '/file/' + encodeURIComponent(file.key) + '?mode=inline', type, name: getDisplayName(file.key) };
                };

                const isTextFile = (key) => {
                    const ext = key.split('.').pop().toLowerCase();
                    return ['txt','md','js','json','html','css','xml','log','yml','toml'].includes(ext);
                };
                const openEditor = async (key) => {
                    const res = await fetch('/api/text-content?key=' + encodeURIComponent(key));
                    if(res.ok) {
                        const text = await res.text();
                        editor.value = { show: true, filename: getDisplayName(key), content: text, key, saving: false, previewMode: false };
                    } else showToast('无法打开文件');
                };
                const saveTextContent = async () => {
                    editor.value.saving = true;
                    try {
                        const res = await fetch('/api/text-content', { method: 'POST', body: JSON.stringify({ key: editor.value.key, content: editor.value.content }) });
                        if(res.ok) showToast('保存成功'); else showToast('保存失败');
                    } catch(e) { showToast('错误'); }
                    editor.value.saving = false;
                };

                const compiledMarkdown = computed(() => {
                    if (editor.value.previewMode && window.marked) {
                        return marked.parse(editor.value.content);
                    }
                    return '';
                });

                const pathParts = computed(() => { if (!currentPath.value) return []; const parts = currentPath.value.split('/').filter(p => p); let accum = ''; return parts.map(p => { accum += p + '/'; return { name: p, fullPath: accum }; }); });
                const getDisplayName = (key) => { const parts = key.split('/'); if (key.endsWith('/')) return parts[parts.length - 2]; return parts[parts.length - 1]; };

                const sortedFiles = computed(() => {
                    let list = files.value;
                    if (searchQuery.value) {
                        const q = searchQuery.value.toLowerCase();
                        list = list.filter(f => f.key.toLowerCase().includes(q));
                    }
                    return list.sort((a, b) => {
                        if (a.isFolder && !b.isFolder) return -1;
                        if (!a.isFolder && b.isFolder) return 1;
                        const field = sortOption.value.field;
                        const order = sortOption.value.order === 'asc' ? 1 : -1;
                        if (field === 'size') return (a.size - b.size) * order;
                        if (field === 'uploaded') return (new Date(a.uploaded) - new Date(b.uploaded)) * order;
                        return a.key.localeCompare(b.key) * order;
                    });
                });

                const openMoveModal = async () => { moveModal.value.target = ''; moveModal.value.folderList = []; moveModal.value.show = true; const res = await fetch('/api/folders/all'); if(res.ok) moveModal.value.folderList = await res.json(); };
                const confirmMove = async () => { let target = moveModal.value.target; if (target && !target.endsWith('/')) target += '/'; await fetch('/api/move', { method: 'POST', body: JSON.stringify({ keys: selectedFiles.value, targetFolder: target }) }); showToast('移动完成'); moveModal.value.show = false; selectedFiles.value = []; refreshFiles(); };
                const createFolder = async () => { if (!createFolderModal.value.name) return; await fetch('/api/create-folder', { method: 'POST', body: JSON.stringify({ folderName: createFolderModal.value.name, currentPath: currentPath.value }) }); createFolderModal.value.show = false; createFolderModal.value.name = ''; showToast('文件夹已创建'); refreshFiles(); };

                const isAllSelected = computed(() => files.value.length > 0 && selectedFiles.value.length === files.value.length);
                const toggleSelectAll = (e) => selectedFiles.value = e.target.checked ? files.value.map(f => f.key) : [];
                const toggleSelection = (key) => { const idx = selectedFiles.value.indexOf(key); if(idx > -1) selectedFiles.value.splice(idx, 1); else selectedFiles.value.push(key); };
                
                const selectAll = () => { selectedFiles.value = files.value.map(f => f.key); };
                const invertSelection = () => { 
                    const currentSet = new Set(selectedFiles.value);
                    selectedFiles.value = files.value.filter(f => !currentSet.has(f.key)).map(f => f.key);
                };

                const isAllSharesSelected = computed(() => shares.value.length > 0 && selectedShares.value.length === shares.value.length);
                const selectAllShares = () => selectedShares.value = shares.value.map(s => s.token);
                const invertShareSelection = () => {
                     const currentSet = new Set(selectedShares.value);
                     selectedShares.value = shares.value.filter(s => !currentSet.has(s.token)).map(s => s.token);
                };
                const toggleShareSelection = (token) => {
                    const idx = selectedShares.value.indexOf(token);
                    if(idx > -1) selectedShares.value.splice(idx, 1);
                    else selectedShares.value.push(token);
                };
                const batchDeleteShares = async () => {
                    closeContextMenu();
                    if (!confirm('确定要撤销选中的 ' + selectedShares.value.length + ' 个分享吗？')) return;
                    await fetch('/api/shares/batch-delete', { method: 'POST', body: JSON.stringify({ tokens: selectedShares.value }) });
                    showToast('批量撤销成功');
                    selectedShares.value = [];
                    fetchShares();
                };

                const batchCopyLinks = async () => {
                    closeContextMenu();
                    if (selectedShares.value.length === 0) return;
                    const links = selectedShares.value.map(token => window.location.origin + '/s/' + token).join('\\n');
                    try {
                        await navigator.clipboard.writeText(links);
                        showToast(\`已复制 \${selectedShares.value.length} 个链接\`);
                    } catch (e) {
                        showToast('复制失败，请确保使用 HTTPS');
                    }
                };

                const restoreTrash = async () => {
                    if(!selectedTrash.value.length) return;
                    await fetch('/api/trash/restore', { method: 'POST', body: JSON.stringify({ keys: selectedTrash.value }) });
                    showToast('已还原 ' + selectedTrash.value.length + ' 个文件');
                    selectedTrash.value = [];
                    fetchTrash();
                };

                const deleteTrashForever = async () => {
                    if(!confirm('确定要彻底删除这些文件吗？此操作无法恢复！')) return;
                    await fetch('/api/trash/delete', { method: 'POST', body: JSON.stringify({ keys: selectedTrash.value }) });
                    showToast('已彻底删除');
                    selectedTrash.value = [];
                    fetchTrash();
                };

                const showContextMenu = (e, item, typeOverride) => {
                    let x = e.clientX; let y = e.clientY; if (window.innerHeight - y < 220) y = y - 220; 
                    
                    if (typeOverride === 'share') { 
                        if (selectedShares.value.length > 1 && selectedShares.value.includes(item.token)) {
                             contextMenu.value = { visible: true, x, y, file: null, type: 'batch-share' };
                        } else {
                             contextMenu.value = { visible: true, x, y, file: item, type: 'share' }; 
                        }
                        return; 
                    }

                    if (selectedFiles.value.includes(item.key) && selectedFiles.value.length > 1) { contextMenu.value = { visible: true, x, y, file: null, type: 'batch' }; } else { if(!selectedFiles.value.includes(item.key)) selectedFiles.value = []; contextMenu.value = { visible: true, x, y, file: item, type: 'single' }; }
                };
                const closeContextMenu = () => { if(contextMenu.value.visible) contextMenu.value.visible = false; };

                const handleMenuAction = async (action) => {
                    const file = contextMenu.value.file; closeContextMenu(); if (!file) return;
                    if (action === 'openShare') window.open('/s/' + file.token, '_blank');
                    else if (action === 'copyShare') { navigator.clipboard.writeText(window.location.origin + '/s/' + file.token); showToast('链接已复制'); }
                    else if (action === 'deleteShare') deleteShare(file.token);
                    else if (action === 'preview') openLightbox(file);
                    else if (action === 'edit') openEditor(file.key);
                    else if (action === 'download') window.location.href = '/file/' + encodeURIComponent(file.key) + '?mode=download';
                    else if (action === 'rename') {
                        const parts = file.key.split('/');
                        const fileName = parts.pop();
                        renameModal.value = { show: true, oldKey: file.key, newKey: fileName };
                    }
                    else if (action === 'share') openShareConfig(file.key);
                    else if (action === 'delete') deleteModal.value = { show: true, key: file.key };
                };

                const openShareConfig = (path) => { shareConfigModal.value = { show: true, path, password: '', expireHours: '', maxViews: '' }; closeContextMenu(); };
                const confirmCreateShare = async () => { const res = await fetch('/api/shares/create', { method: 'POST', body: JSON.stringify(shareConfigModal.value) }); const data = await res.json(); if (data.success) { showToast('分享链接已生成'); shareConfigModal.value.show = false; navigator.clipboard.writeText(window.location.origin + '/s/' + data.token); showToast('链接已复制到剪贴板'); } };

                const batchDelete = async () => { closeContextMenu(); if (!confirm('确定要删除选中的 ' + selectedFiles.value.length + ' 个项目吗？\\n(将会移入回收站)')) return; await fetch('/api/batch-delete', { method: 'POST', body: JSON.stringify({ keys: selectedFiles.value }) }); showToast('已移入回收站'); selectedFiles.value = []; refreshFiles(); };
                
                const confirmRename = async () => {
                    const { oldKey, newKey } = renameModal.value;
                    const parts = oldKey.split('/');
                    parts.pop(); 
                    const newFullPath = parts.join('/') + (parts.length > 0 ? '/' : '') + newKey;

                    if (!newKey || newFullPath === oldKey) { renameModal.value.show = false; return; }
                    
                    await fetch('/api/rename', { method: 'POST', body: JSON.stringify({ oldKey, newKey: newFullPath }) });
                    showToast('重命名成功'); 
                    refreshFiles(); 
                    renameModal.value.show = false; 
                };

                const confirmDelete = async () => { await fetch('/api/delete-file', { method: 'POST', body: JSON.stringify({ key: deleteModal.value.key }) }); refreshFiles(); showToast('已移入回收站'); deleteModal.value.show = false; };
                
                // 处理文件选择 (input change)
                const handleFiles = (fileList) => {
                    const list = Array.from(fileList);
                    if(!list.length) return;
                    list.forEach(file => {
                        // 相对路径逻辑: webkitRelativePath (来自input) > customRelativePath (来自drop递归) > name
                        const relativePath = file.webkitRelativePath || file.customRelativePath || file.name;
                        uploadQueue.value.push({ 
                            id: Date.now() + Math.random(), 
                            file, 
                            relativePath: relativePath,
                            progress: 0, 
                            status: 'pending', 
                            statusText: '等待中...' 
                        });
                    });
                    processQueue();
                    if(currentView.value !== 'uploads') { currentView.value = 'uploads'; showToast('已加入上传队列'); }
                };

                // 递归处理拖拽 (支持文件夹)
                const handleDrop = async (e) => {
                    const items = e.dataTransfer.items;
                    if (!items) return;
                    const files = [];
                    const queuePromises = [];

                    const traverseFileTree = (item, path = '') => {
                        return new Promise((resolve) => {
                            if (item.isFile) {
                                item.file((file) => {
                                    file.customRelativePath = path + file.name;
                                    files.push(file);
                                    resolve();
                                });
                            } else if (item.isDirectory) {
                                const dirReader = item.createReader();
                                const readEntries = () => {
                                    dirReader.readEntries(async (entries) => {
                                        if (entries.length > 0) {
                                            await Promise.all(entries.map(entry => traverseFileTree(entry, path + item.name + '/')));
                                            readEntries(); 
                                        } else {
                                            resolve();
                                        }
                                    });
                                };
                                readEntries();
                            } else {
                                resolve();
                            }
                        });
                    };

                    for (let i = 0; i < items.length; i++) {
                        const item = items[i].webkitGetAsEntry();
                        if (item) queuePromises.push(traverseFileTree(item));
                    }

                    await Promise.all(queuePromises);
                    handleFiles(files);
                };

                const processQueue = async () => { if (isUploading.value) return; const item = uploadQueue.value.find(i => i.status === 'pending'); if (!item) return; isUploading.value = true; item.status = 'uploading'; item.statusText = '上传中...'; try { await uploadItem(item); item.status = 'success'; item.statusText = '完成'; } catch (e) { item.status = 'error'; item.statusText = '失败'; } finally { isUploading.value = false; fetchUploadHistory(); processQueue(); } };
                
                const uploadItem = (item) => { 
                    return new Promise((resolve, reject) => { 
                        const formData = new FormData(); 
                        formData.append('file', item.file); 
                        formData.append('folder', currentPath.value); 
                        formData.append('relativePath', item.relativePath);
                        const xhr = new XMLHttpRequest(); 
                        xhr.open('POST', '/api/upload', true); 
                        xhr.upload.onprogress = (e) => { if (e.lengthComputable) item.progress = Math.round((e.loaded / e.total) * 100); }; 
                        xhr.onload = () => { if (xhr.status === 200) resolve(); else reject(); }; 
                        xhr.onerror = reject; 
                        xhr.send(formData); 
                    }); 
                };

                const clearUploadHistory = async () => { if(!confirm('确定要清空所有上传历史记录吗？\\n此操作不会删除文件，仅清除列表日志。')) return; await fetch('/api/uploads/clear-history', { method: 'POST' }); uploadHistory.value = []; showToast('历史记录已清空'); };

                const handleAuth = async () => { const ep = serverInitialized.value ? '/api/login' : '/api/setup'; const res = await fetch(ep, { method: 'POST', body: JSON.stringify(authForm.value) }); const data = await res.json(); if (data.success) { if(!serverInitialized.value) { alert('初始化完成'); serverInitialized.value = true; } else { isLoggedIn.value = true; fetchUploadHistory(); } } else alert(data.msg); };
                const logout = () => { document.cookie = "${SESSION_KEY}=; path=/; max-age=0"; isLoggedIn.value = false; };
                const showToast = (msg) => { toast.value = { show: true, msg }; setTimeout(() => toast.value.show = false, 3000); };
                const fetchUploadHistory = async () => { const res = await fetch('/api/uploads/history'); if(res.ok) uploadHistory.value = await res.json(); };
                const fetchShares = async () => { const res = await fetch('/api/shares'); if(res.ok) shares.value = await res.json(); };
                const deleteShare = async (token) => { await fetch('/api/shares/delete', { method: 'POST', body: JSON.stringify({ token }) }); fetchShares(); };
                const updatePassword = async () => { await fetch('/api/settings/password', { method: 'POST', body: JSON.stringify({ password: newPassword.value }) }); showToast('密码已更新'); newPassword.value=''; };
                const formatSize = (bytes) => { if (bytes === 0) return '0 B'; const k = 1024; const i = Math.floor(Math.log(bytes) / Math.log(k)); return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + ['B', 'KB', 'MB', 'GB', 'TB'][i]; };
                const getFileIcon = (file) => { if (file.isFolder) return 'fa-solid fa-folder'; const ext = file.key.split('.').pop().toLowerCase(); if(['jpg','png','gif','webp'].includes(ext)) return 'fa-regular fa-image'; if(['mp4','mov','webm'].includes(ext)) return 'fa-regular fa-file-video'; if(['mp3','wav'].includes(ext)) return 'fa-regular fa-file-audio'; if(['pdf'].includes(ext)) return 'fa-regular fa-file-pdf'; if(['zip','rar','7z'].includes(ext)) return 'fa-regular fa-file-zipper'; return 'fa-regular fa-file'; };
                const activeUploadCount = computed(() => uploadQueue.value.filter(i => i.status === 'uploading' || i.status === 'pending').length);

                return {
                    serverInitialized, isLoggedIn, mobileMenuOpen, currentView,
                    files, shares, uploadQueue, uploadHistory, activeUploadCount, selectedFiles, isAllSelected, currentPath, pathParts,
                    selectedShares, isShareSelectionMode, isAllSharesSelected, selectAllShares, invertShareSelection, toggleShareSelection, toggleShareSelectionMode, batchDeleteShares, batchCopyLinks,
                    trashFiles, selectedTrash, restoreTrash, deleteTrashForever, stats,
                    authForm, newPassword, toast, contextMenu, renameModal, deleteModal, createFolderModal, moveModal, shareConfigModal, lightbox, editor,
                    searchQuery, sortedFiles, viewMode, sortOption, isSelectionMode, compiledMarkdown,
                    handleAuth, logout, switchView, handleFiles, handleDrop,
                    refreshFiles, fetchShares, deleteShare, updatePassword, fetchTrash, fetchStats,
                    showContextMenu, closeContextMenu, handleMenuAction, confirmRename, confirmDelete, createFolder, confirmMove, openMoveModal,
                    toggleSelectAll, toggleSelection, batchDelete, navigateTo, handleRowClick, getDisplayName, openShareConfig, confirmCreateShare,
                    fetchUploadHistory, formatSize, getFileIcon, openLightbox, openEditor, saveTextContent, isTextFile, toggleSelectionMode,
                    selectAll, invertSelection, clearUploadHistory
                };
            }
        }).mount('#app');
    </script>
</body>
</html>
  `;
}