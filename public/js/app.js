/* 공통 헬퍼: API 호출, 클립보드 복사, 토스트, 네비 활성화 */
(function () {
  'use strict';

  // 현재 페이지에 맞춰 네비게이션 활성화
  function highlightNav() {
    const path = location.pathname.replace(/\/index\.html$/, '/');
    document.querySelectorAll('.nav nav a').forEach((a) => {
      const href = a.getAttribute('href');
      if (href === path || (href !== '/' && path.startsWith(href))) a.classList.add('active');
      if (path === '/' && href === '/') a.classList.add('active');
    });
  }

  // fetch → JSON 래퍼
  async function api(path, opts = {}) {
    const res = await fetch(path, opts);
    return res.json();
  }
  async function postJSON(path, body) {
    return api(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // 토스트
  let toastTimer;
  function toast(msg, kind = '') {
    let t = document.getElementById('toast');
    if (!t) {
      t = document.createElement('div');
      t.id = 'toast';
      t.style.cssText =
        'position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(20px);' +
        'background:#182334;border:1px solid #243246;color:#e6edf3;padding:11px 18px;border-radius:10px;' +
        'font-weight:600;font-size:14px;box-shadow:0 8px 24px rgba(0,0,0,.4);opacity:0;transition:.2s;z-index:200;';
      document.body.appendChild(t);
    }
    t.textContent = msg;
    t.style.borderColor = kind === 'ok' ? '#1c4d3e' : kind === 'bad' ? '#5b2330' : '#243246';
    requestAnimationFrame(() => { t.style.opacity = '1'; t.style.transform = 'translateX(-50%) translateY(0)'; });
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      t.style.opacity = '0'; t.style.transform = 'translateX(-50%) translateY(20px)';
    }, 1800);
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      toast('📋 복사됨: ' + (text.length > 40 ? text.slice(0, 40) + '…' : text), 'ok');
    } catch {
      // 클립보드 권한이 없을 때 폴백
      const ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); toast('📋 복사됨', 'ok'); } catch { toast('복사 실패', 'bad'); }
      ta.remove();
    }
  }

  // 결과 행을 표로 렌더링
  function renderTable(rows, opts = {}) {
    if (!rows || !rows.length) return '<p class="muted">결과 없음</p>';
    const cols = Object.keys(rows[0]);
    const leakCols = opts.leakCols || [];
    let html = '<div class="table-wrap"><table class="data"><thead><tr>';
    for (const c of cols) html += `<th>${escapeHtml(c)}</th>`;
    html += '</tr></thead><tbody>';
    for (const r of rows) {
      html += '<tr>';
      for (const c of cols) {
        const leak = leakCols.includes(c);
        html += `<td class="${leak ? 'leak' : ''}">${escapeHtml(r[c])}</td>`;
      }
      html += '</tr>';
    }
    html += '</tbody></table></div>';
    return html;
  }

  // 전역 노출
  window.App = { api, postJSON, escapeHtml, toast, copyText, renderTable };
  document.addEventListener('DOMContentLoaded', highlightNav);
})();
