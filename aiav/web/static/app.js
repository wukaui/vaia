/* 首页：拖拽上传 + 轮询进度 + 展示结论。原生 JS，不引任何前端依赖。 */
(function () {
  const drop = document.getElementById('drop');
  const input = document.getElementById('file');
  const go = document.getElementById('go');
  const reset = document.getElementById('reset');
  const picked = document.getElementById('picked');
  const state = document.getElementById('state');
  const result = document.getElementById('result');
  const log = document.getElementById('log');

  let chosen = null;
  let timer = null;

  function choose(f) {
    chosen = f || null;
    if (!chosen) {
      picked.textContent = '还没有选择文件';
      go.disabled = true;
      return;
    }
    picked.textContent = '已选择：' + chosen.name + '（' + fmtSize(chosen.size) + '）';
    go.disabled = false;
  }

  function fmtSize(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1024 / 1024).toFixed(1) + ' MB';
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
  }

  drop.addEventListener('click', () => input.click());
  input.addEventListener('change', () => choose(input.files[0]));
  ['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => {
    e.preventDefault(); drop.classList.add('hot');
  }));
  ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => {
    e.preventDefault(); drop.classList.remove('hot');
  }));
  drop.addEventListener('drop', e => {
    const files = e.dataTransfer && e.dataTransfer.files;
    if (files && files.length) choose(files[0]);
  });
  reset.addEventListener('click', () => {
    if (timer) { clearInterval(timer); timer = null; }
    input.value = '';
    choose(null);
    state.textContent = '';
    result.className = 'meta';
    result.textContent = '还没有任务。';
    log.hidden = true;
  });

  loadSettings();

  go.addEventListener('click', async () => {
    if (!chosen) return;
    if (timer) { clearInterval(timer); timer = null; }
    go.disabled = true;
    state.textContent = '上传中…';
    result.className = 'meta';
    result.textContent = '已提交，等待队列…';
    log.hidden = true;

    const fd = new FormData();
    fd.append('file', chosen, chosen.name);

    let resp;
    try {
      resp = await fetch('/api/scan', { method: 'POST', body: fd });
    } catch (err) {
      state.textContent = '';
      result.className = 'error';
      result.textContent = '请求失败：' + err;
      go.disabled = false;
      return;
    }

    if (resp.status === 413) {
      state.textContent = '';
      result.className = 'error';
      result.textContent = '❌ 文件超过大小上限（413），换个小点的文件。';
      go.disabled = false;
      return;
    }
    if (resp.status === 429) {
      state.textContent = '';
      result.className = 'error';
      result.textContent = '⏳ 扫描队列已满（429）：单并发，等当前任务跑完再传。';
      go.disabled = false;
      return;
    }
    if (!resp.ok) {
      const body = await resp.text();
      state.textContent = '';
      result.className = 'error';
      result.textContent = 'HTTP ' + resp.status + '：' + esc(body).slice(0, 300);
      go.disabled = false;
      return;
    }

    const data = await resp.json();
    state.textContent = '任务 ' + data.job_id.slice(0, 8) + '…';
    result.textContent = '任务已入队：' + esc(data.file) + '（' + esc(data.status) + '）';
    poll(data.job_id);
  });

  // ---------------- 扫描参数（服务端 web-settings.json） ----------------
  const FIELDS = ['ai', 'triage', 'ai_threshold', 'ai_threshold_low',
                  'triage_threshold', 'triage_entry_gate',
                  'deep_evidence_threshold', 'token_budget'];
  const saveState = document.getElementById('save-state');

  function readSettings() {
    const out = {};
    FIELDS.forEach(k => {
      const el = document.getElementById('p-' + k);
      if (!el) return;
      if (el.type === 'checkbox') { out[k] = el.checked; return; }
      const v = parseInt(el.value, 10);
      out[k] = Number.isNaN(v) ? 0 : v;
    });
    return out;
  }

  function writeSettings(params) {
    FIELDS.forEach(k => {
      const el = document.getElementById('p-' + k);
      if (!el || params[k] === undefined || params[k] === null) return;
      if (el.type === 'checkbox') el.checked = !!params[k];
      else el.value = params[k];
    });
  }

  async function loadSettings() {
    try {
      const r = await fetch('/api/settings');
      if (r.ok) writeSettings((await r.json()).params || {});
    } catch (err) { /* 加载失败就用服务端渲染的初值 */ }
  }

  const saveBtn = document.getElementById('save');
  if (saveBtn) {
    saveBtn.addEventListener('click', async () => {
      saveState.textContent = '保存中…';
      try {
        const r = await fetch('/api/settings', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(readSettings()),
        });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const d = await r.json();
        writeSettings(d.params);
        saveState.textContent = '已保存（对新任务生效）：' +
          FIELDS.map(k => k + '=' + d.params[k]).join(' · ');
      } catch (err) {
        saveState.textContent = '保存失败：' + err;
      }
    });
  }

  const goLocal = document.getElementById('go-local');
  if (goLocal) {
    goLocal.addEventListener('click', async () => {
      const pathEl = document.getElementById('localpath');
      const st = document.getElementById('local-state');
      const path = (pathEl.value || '').trim();
      if (!path) { st.textContent = '先填一个路径'; return; }
      if (timer) { clearInterval(timer); timer = null; }
      goLocal.disabled = true;
      st.textContent = '提交中…';
      result.className = 'meta';
      result.textContent = '已提交，等待队列…';
      log.hidden = true;

      let resp;
      try {
        resp = await fetch('/api/scan-local', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path: path }),
        });
      } catch (err) {
        st.textContent = '';
        result.className = 'error';
        result.textContent = '请求失败：' + err;
        goLocal.disabled = false;
        return;
      }
      if (!resp.ok) {
        const body = await resp.text();
        st.textContent = '';
        result.className = 'error';
        result.textContent = 'HTTP ' + resp.status + '：' + esc(body).slice(0, 300);
        goLocal.disabled = false;
        return;
      }
      const data = await resp.json();
      st.textContent = '任务 ' + data.job_id.slice(0, 8) + '…';
      result.textContent = '已入队：' + esc(data.file);
      poll(data.job_id);
    });
  }

  function poll(jobId) {
    let ticks = 0;
    timer = setInterval(async () => {
      ticks += 1;
      let resp;
      try {
        resp = await fetch('/api/scan/' + jobId);
      } catch (err) {
        return; // 网络抖动就下一轮再试
      }
      if (!resp.ok) return;
      const j = await resp.json();
      state.textContent = '状态：' + j.status + '（第 ' + ticks + ' 次轮询）';
      if (j.status === 'queued' || j.status === 'running') {
        result.textContent = '扫描中…（' + esc(j.file) + '）';
        return;
      }
      clearInterval(timer);
      timer = null;
      go.disabled = false;
      const gl = document.getElementById('go-local');
      if (gl) gl.disabled = false;
      render(j);
    }, 700);
  }

  function render(j) {
    if (j.status === 'error') {
      result.className = 'error';
      result.textContent = '扫描出错：' + esc(j.error);
      return;
    }
    const s = j.summary || {};
    const rows = (s.per_file || []).map(f => `
      <tr>
        <td class="rowfile">${esc(f.name)}</td>
        <td><span class="badge ${esc(f.risk)}">${riskText(f.risk)}</span></td>
        <td>${esc(f.category)}</td>
        <td>${esc(f.summary)}</td>
        <td class="dim">${esc(f.report_label)}</td>
      </tr>`).join('');

    result.className = '';
    result.innerHTML = `
      <div class="cards">
        <div class="card"><span>总数</span><b>${s.total || 0}</b></div>
        <div class="card"><span>安全</span><b style="color:#2e7d32">${s.clean || 0}</b></div>
        <div class="card"><span>可疑</span><b style="color:#ef6c00">${s.suspicious || 0}</b></div>
        <div class="card"><span>恶意</span><b style="color:#c62828">${s.malicious || 0}</b></div>
        <div class="card"><span>AI 研判</span><b>${s.agent_used || 0}</b></div>
      </div>
      <div class="meta">${s.ai_enabled
        ? 'AI 判决档：已生效'
        : (s.ai_requested ? 'AI 判决档：<b>请求了但未生效</b>（' + esc(s.ai_fallback || '') + '）→ 结论为确定性判定（规则档）'
                          : 'AI 判决档：关闭 → 结论为<b>确定性判定（规则档，未调用模型）</b>')}</div>
      <div class="meta">来源：${esc(s.source || 'upload')}　·　本轮参数：${esc(Object.entries(s.params || {}).map(([k, v]) => k + '=' + v).join(' · '))}</div>
      ${s.truncated ? '<div class="warn">⚠ 文件数超过单次上限 ' + (s.max_local_files || '') + '，只扫了前一部分</div>' : ''}
      ${(s.skipped && Object.keys(s.skipped).length)
        ? '<div class="meta">未进扫描：' + esc(Object.entries(s.skipped).map(([k, v]) => k + ' ' + v).join('、')) + '</div>' : ''}
      <div class="scroll-x">
        <table>
          <thead><tr><th>文件</th><th>判定</th><th>类别</th><th>结论</th><th>结论档位</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <div class="toolbar"><a href="${esc(j.report_url)}">打开完整 HTML 报告 →</a></div>`;
  }

  function riskText(risk) {
    return { clean: '安全', suspicious: '可疑', malicious: '恶意' }[risk] || risk;
  }
})();
