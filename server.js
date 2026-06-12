'use strict';

const express = require('express');
const path = require('node:path');

const dbModule = require('./src/db');
const strategies = require('./src/strategies');
const waf = require('./src/waf');
const bruteforce = require('./src/bruteforce');

const app = express();
const PORT = process.env.PORT || 3000;

// DB 초기화 (스키마 + 시드)
dbModule.init();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const VALID_MODES = ['vulnerable', 'whitelist', 'orm', 'parameterized'];
function normMode(m) {
  return VALID_MODES.includes(m) ? m : 'vulnerable';
}
function wafOn(v) {
  return v === true || v === 'on' || v === '1' || v === 'true';
}

// ───────────────────────────── 로그인 ─────────────────────────────
app.post('/api/login', (req, res) => {
  const db = dbModule.getDb();
  const username = String(req.body.username ?? '');
  const password = String(req.body.password ?? '');
  const mode = normMode(req.body.mode);
  const useWaf = wafOn(req.body.waf);

  // 1) WAF (요청 단계 선차단) — 켜져 있으면 쿼리 도달 전에 검사
  if (useWaf) {
    const verdict = waf.inspect({ username, password });
    if (verdict.blocked) {
      return res.json({
        stage: 'waf',
        wafEnabled: true,
        blocked: true,
        blockedBy: 'waf',
        wafVerdict: verdict,
        authenticated: false,
        mode,
        note: verdict.reason,
        bruteforce: bruteforce.status(username),
      });
    }
  }

  // 2) 무차별 대입 잠금 확인
  if (bruteforce.isLocked(username)) {
    return res.json({
      stage: 'bruteforce',
      blocked: true,
      blockedBy: 'bruteforce',
      authenticated: false,
      mode,
      wafEnabled: useWaf,
      note: `계정 '${username}'(이)가 반복 로그인 실패로 일시 잠금되었습니다. 잠시 후 다시 시도하세요.`,
      bruteforce: bruteforce.status(username),
    });
  }

  // 3) 모드별 쿼리 실행
  const result = strategies.login(db, { username, password, mode });

  // 4) 무차별 대입 카운터 갱신
  if (result.authenticated) {
    bruteforce.recordSuccess(username);
    result.bruteforce = bruteforce.status(username);
  } else if (!result.blocked) {
    result.bruteforce = bruteforce.recordFailure(username);
  } else {
    result.bruteforce = bruteforce.status(username);
  }

  result.wafEnabled = useWaf;
  res.json(result);
});

// ───────────────────────────── 게시판 검색 ─────────────────────────────
app.get('/api/search', (req, res) => {
  const db = dbModule.getDb();
  const q = String(req.query.q ?? '');
  const mode = normMode(req.query.mode);
  const useWaf = wafOn(req.query.waf);

  if (useWaf) {
    const verdict = waf.inspect({ q });
    if (verdict.blocked) {
      return res.json({
        stage: 'waf', wafEnabled: true, blocked: true, blockedBy: 'waf',
        wafVerdict: verdict, rows: [], count: 0, mode, note: verdict.reason,
      });
    }
  }

  const result = strategies.search(db, { q, mode });
  result.wafEnabled = useWaf;
  res.json(result);
});

// ───────────────────────────── 회원가입 ─────────────────────────────
app.post('/api/signup', (req, res) => {
  const db = dbModule.getDb();
  const username = String(req.body.username ?? '');
  const password = String(req.body.password ?? '');
  const email = String(req.body.email ?? '');
  const mode = normMode(req.body.mode);
  const result = strategies.signup(db, { username, password, email, mode });
  res.json(result);
});

// ───────────────────────────── 데이터 들여다보기 ─────────────────────────────
// "공격자가 노리는 실제 데이터"를 보여주는 용도 (로컬 데모 전용)
app.get('/api/users', (req, res) => {
  const db = dbModule.getDb();
  const rows = db.prepare('SELECT id, username, password, email, role, secret FROM users').all();
  res.json({ rows, count: rows.length });
});

app.get('/api/posts', (req, res) => {
  const db = dbModule.getDb();
  const rows = db.prepare('SELECT id, title, body, author, visible FROM posts').all();
  res.json({ rows, count: rows.length });
});

// ───────────────────────────── DB 관리 (로컬 데모 전용 콘솔) ─────────────────────────────
// 교육용 샌드박스: 사용자가 직접 SQL을 실행해 행/열을 추가·수정하고, 초기화로 되돌린다.
app.get('/api/db/tables', (req, res) => {
  const db = dbModule.getDb();
  const tables = db
    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
    .all();
  const out = tables.map((t) => {
    const columns = db.prepare(`PRAGMA table_info(${t.name})`).all()
      .map((c) => ({ name: c.name, type: c.type, pk: c.pk, notnull: c.notnull }));
    const count = db.prepare(`SELECT COUNT(*) AS n FROM ${t.name}`).get().n;
    return { name: t.name, columns, count };
  });
  res.json({ tables: out });
});

app.get('/api/db/table/:name', (req, res) => {
  const db = dbModule.getDb();
  const name = String(req.params.name);
  // 식별자 화이트리스트: 실제 존재하는 테이블만 허용
  const exists = db
    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name = ?")
    .get(name);
  if (!exists) return res.json({ ok: false, error: `테이블 '${name}'을(를) 찾을 수 없습니다.` });
  const columns = db.prepare(`PRAGMA table_info(${name})`).all()
    .map((c) => ({ name: c.name, type: c.type, pk: c.pk, notnull: c.notnull }));
  const rows = db.prepare(`SELECT * FROM ${name}`).all();
  res.json({ ok: true, name, columns, rows, count: rows.length });
});

app.post('/api/db/exec', (req, res) => {
  const db = dbModule.getDb();
  const sql = String(req.body.sql ?? '').trim();
  if (!sql) return res.json({ ok: false, error: 'SQL을 입력하세요.' });
  try {
    if (/^\s*(SELECT|PRAGMA|WITH|EXPLAIN)\b/i.test(sql)) {
      const rows = db.prepare(sql).all();
      return res.json({ ok: true, kind: 'select', rows, count: rows.length });
    }
    if (/^\s*(INSERT|UPDATE|DELETE|REPLACE)\b/i.test(sql)) {
      const info = db.prepare(sql).run();
      return res.json({
        ok: true, kind: 'dml',
        changes: info.changes,
        lastInsertRowid: Number(info.lastInsertRowid),
        note: `${info.changes}개 행이 영향을 받았습니다.`,
      });
    }
    // CREATE / ALTER / DROP 등 DDL
    db.exec(sql);
    return res.json({ ok: true, kind: 'ddl', note: '스키마가 변경되었습니다.' });
  } catch (e) {
    return res.json({ ok: false, error: e.message });
  }
});

// ───────────────────────────── 상태/초기화 ─────────────────────────────
app.get('/api/bruteforce/:username', (req, res) => {
  res.json(bruteforce.status(String(req.params.username)));
});

app.post('/api/reset', (req, res) => {
  dbModule.reset();
  bruteforce.resetAll();
  res.json({ ok: true, note: 'DB와 무차별 대입 카운터를 초기화했습니다.' });
});

// WAF 시그니처 목록(가이드 표시용)
app.get('/api/waf/signatures', (req, res) => {
  res.json({ signatures: waf.SIGNATURES.map((s) => ({ name: s.name, pattern: s.re.source })) });
});

app.listen(PORT, () => {
  console.log(`\n  🛡️  SQL 인젝션 방어 가이드 사이트`);
  console.log(`  ➜  http://localhost:${PORT}\n`);
});
