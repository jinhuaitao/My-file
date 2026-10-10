const fs = require('fs');
const path = require('path');

const dir = __dirname;
const backend = fs.readFileSync(path.join(dir, '_backend.js'), 'utf8');
const ui = fs.readFileSync(path.join(dir, '_ui_1.html'), 'utf8')
         + fs.readFileSync(path.join(dir, '_ui_2.html'), 'utf8');

// 把 HTML 安全地嵌进 JS 模板字符串：反斜杠、反引号、${ 都要转义
const escaped = ui
    .replace(/\\/g, '\\\\')
    .replace(/`/g, '\\`')
    .replace(/\$\{/g, '\\${');

const tail = '\nfunction getHtml(isInitialized) {\n'
    + '    return `' + escaped + '`.replace(\'__SERVER_INITIALIZED__\', String(isInitialized));\n'
    + '}\n';

fs.writeFileSync(path.join(dir, 'index.js'), backend.replace(/\s*$/, '\n') + tail);

// 自检：拼接后的文件里，模板字符串定界符必须是偶数个
const out = fs.readFileSync(path.join(dir, 'index.js'), 'utf8');
const ticks = (out.match(/`/g) || []).length;
console.log('index.js bytes :', out.length);
console.log('backticks      :', ticks, ticks % 2 === 0 ? '(even, ok)' : '(ODD -> BROKEN)');
console.log('placeholder    :', out.includes('__SERVER_INITIALIZED__') ? 'present' : 'MISSING');
