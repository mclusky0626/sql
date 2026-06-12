'use strict';

const { models } = require('./orm');

/**
 * 모드별 쿼리 전략 모음.
 *
 * 같은 입력을 4가지 방식으로 처리해 비교한다:
 *   - vulnerable    : 문자열을 그대로 이어 붙인 쿼리 (취약, 인젝션 성공)
 *   - whitelist     : 화이트리스트 입력 검증으로 공격 입력을 차단
 *   - orm           : ORM 모델 계층 사용 (내부적으로 파라미터 바인딩)
 *   - parameterized : ? 자리표시자 + 값 바인딩
 *
 * 각 전략은 { authenticated/rows, sql, queryHtml, params, note ... } 형태를 돌려준다.
 * sql/queryHtml 은 "실제로 실행된 쿼리"를 화면에 보여주기 위한 것이다.
 */

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// 취약 쿼리에서 "사용자 입력이 들어간 부분"을 빨갛게 강조한 HTML을 만든다.
function mark(s) {
  return `<mark class="inj">${escapeHtml(s)}</mark>`;
}

// ───────────────────────── 화이트리스트 검증 ─────────────────────────
const USERNAME_RE = /^[A-Za-z0-9_]{1,32}$/;
const PASSWORD_BLOCK_RE = /['";]|--|\/\*|\bOR\b|\bUNION\b/i;

function whitelistValidate(username, password) {
  if (!USERNAME_RE.test(username)) {
    return {
      ok: false,
      field: 'username',
      reason: `아이디는 영문/숫자/_ 만 1~32자로 허용됩니다. 입력값이 규칙을 위반했습니다.`,
    };
  }
  if (password != null && PASSWORD_BLOCK_RE.test(String(password))) {
    return {
      ok: false,
      field: 'password',
      reason: `비밀번호에 허용되지 않은 문자/키워드(따옴표, 세미콜론, 주석, OR, UNION 등)가 포함되어 차단했습니다.`,
    };
  }
  return { ok: true };
}

// ───────────────────────────── 로그인 ─────────────────────────────
function login(db, { username, password, mode }) {
  const { User } = models(db);
  const u = username ?? '';
  const p = password ?? '';

  if (mode === 'vulnerable') {
    // ❌ 절대 따라 하면 안 되는 코드: 입력을 그대로 문자열에 이어 붙인다.
    const sql = `SELECT id, username, role, email FROM users WHERE username = '${u}' AND password = '${p}'`;
    const queryHtml =
      `SELECT id, username, role, email FROM users WHERE username = '${mark(u)}' AND password = '${mark(p)}'`;
    let rows = [];
    let error = null;
    try {
      rows = db.prepare(sql).all();
    } catch (e) {
      error = e.message;
    }
    const authenticated = rows.length > 0;
    return {
      mode,
      authenticated,
      user: authenticated ? rows[0] : null,
      matchedRows: rows.length,
      sql,
      queryHtml,
      params: null,
      error,
      note: authenticated
        ? `로그인 성공. 입력한 따옴표/주석이 SQL 문법으로 해석되어 비밀번호 검사를 우회했습니다. (반환 행 ${rows.length}개)`
        : `반환된 행이 없어 로그인 실패. 페이로드를 바꿔 다시 시도해 보세요.`,
    };
  }

  if (mode === 'whitelist') {
    const v = whitelistValidate(u, p);
    if (!v.ok) {
      return {
        mode,
        authenticated: false,
        user: null,
        blocked: true,
        blockedBy: 'whitelist',
        field: v.field,
        sql: null,
        queryHtml: `<span class="muted">— 입력 검증 단계에서 차단되어 쿼리를 실행하지 않음 —</span>`,
        params: null,
        note: `화이트리스트 위반: ${v.reason}`,
      };
    }
    // 검증 통과 → 안전하게 파라미터화 쿼리로 인증
    const sql = `SELECT id, username, role, email FROM users WHERE username = ? AND password = ?`;
    const row = db.prepare(sql).get(u, p);
    return {
      mode,
      authenticated: !!row,
      user: row || null,
      matchedRows: row ? 1 : 0,
      sql,
      queryHtml: escapeHtml(sql),
      params: [u, p],
      note: row
        ? `입력 검증 통과 후 파라미터화 쿼리로 인증 성공.`
        : `입력 검증은 통과했지만 일치하는 계정이 없어 로그인 실패.`,
    };
  }

  if (mode === 'orm') {
    // User.findOne({ where: { username, password } }) — 값은 전부 ? 에 바인딩된다.
    const { row, sql, params } = User.findOne(
      { username: u, password: p },
      ['id', 'username', 'role', 'email']
    );
    return {
      mode,
      authenticated: !!row,
      user: row || null,
      matchedRows: row ? 1 : 0,
      sql,
      queryHtml: escapeHtml(sql),
      params,
      note: row
        ? `ORM이 생성한 파라미터화 쿼리로 인증 성공.`
        : `입력값이 '문자열 값'으로만 바인딩되어 인젝션이 통하지 않습니다. 일치 계정 없음 → 로그인 실패.`,
    };
  }

  // parameterized (기본 권장 방어)
  const sql = `SELECT id, username, role, email FROM users WHERE username = ? AND password = ?`;
  const row = db.prepare(sql).get(u, p);
  return {
    mode: 'parameterized',
    authenticated: !!row,
    user: row || null,
    matchedRows: row ? 1 : 0,
    sql,
    queryHtml: escapeHtml(sql),
    params: [u, p],
    note: row
      ? `파라미터화 쿼리로 인증 성공.`
      : `? 자리표시자에 값으로만 바인딩되므로 따옴표/주석이 문법으로 해석되지 않습니다. 일치 계정 없음 → 로그인 실패.`,
  };
}

// ───────────────────────────── 게시판 검색 ─────────────────────────────
// 공개 게시글 제목을 검색한다. 취약 모드에서는 UNION 인젝션으로 users 테이블 유출 가능.
function search(db, { q, mode }) {
  const { Post } = models(db);
  const term = q ?? '';

  if (mode === 'vulnerable') {
    const sql = `SELECT id, title, body, author FROM posts WHERE visible = 1 AND title LIKE '%${term}%'`;
    const queryHtml =
      `SELECT id, title, body, author FROM posts WHERE visible = 1 AND title LIKE '%${mark(term)}%'`;
    let rows = [];
    let error = null;
    try {
      rows = db.prepare(sql).all();
    } catch (e) {
      error = e.message;
    }
    return {
      mode,
      rows,
      count: rows.length,
      sql,
      queryHtml,
      params: null,
      error,
      note: error
        ? `쿼리 오류: ${error}`
        : `검색 결과 ${rows.length}건. UNION 페이로드를 쓰면 다른 테이블(users)의 데이터까지 함께 끌려 나옵니다.`,
    };
  }

  if (mode === 'whitelist') {
    // 검색어는 글자/숫자/공백/한글 정도만 허용 (따옴표/주석/키워드 차단)
    if (PASSWORD_BLOCK_RE.test(term) || /[%_]/.test(term)) {
      return {
        mode,
        rows: [],
        count: 0,
        blocked: true,
        blockedBy: 'whitelist',
        sql: null,
        queryHtml: `<span class="muted">— 입력 검증 단계에서 차단되어 쿼리를 실행하지 않음 —</span>`,
        params: null,
        note: `화이트리스트 위반: 검색어에 허용되지 않은 문자(따옴표/주석/와일드카드/SQL 키워드)가 포함되었습니다.`,
      };
    }
    const sql = `SELECT id, title, body, author FROM posts WHERE visible = 1 AND title LIKE ?`;
    const rows = db.prepare(sql).all(`%${term}%`);
    return {
      mode, rows, count: rows.length, sql,
      queryHtml: escapeHtml(sql), params: [`%${term}%`],
      note: `입력 검증 통과 후 파라미터화 검색. 결과 ${rows.length}건.`,
    };
  }

  if (mode === 'orm') {
    const { rows, sql, params } = Post.find({
      where: { visible: 1 },
      like: { title: term },
      columns: ['id', 'title', 'body', 'author'],
    });
    return {
      mode, rows, count: rows.length, sql,
      queryHtml: escapeHtml(sql), params,
      note: `ORM이 LIKE 조건을 ? 로 바인딩합니다. 인젝션 불가. 결과 ${rows.length}건.`,
    };
  }

  // parameterized
  const sql = `SELECT id, title, body, author FROM posts WHERE visible = 1 AND title LIKE ?`;
  const rows = db.prepare(sql).all(`%${term}%`);
  return {
    mode: 'parameterized', rows, count: rows.length, sql,
    queryHtml: escapeHtml(sql), params: [`%${term}%`],
    note: `검색어가 LIKE 값으로만 바인딩되어 UNION/주석이 문법으로 해석되지 않습니다. 결과 ${rows.length}건.`,
  };
}

// ───────────────────────────── 회원가입 ─────────────────────────────
function signup(db, { username, password, email, mode }) {
  const { User } = models(db);
  const u = username ?? '';
  const p = password ?? '';
  const e = email ?? '';

  // 중복 체크
  const exists = db.prepare('SELECT 1 FROM users WHERE username = ?').get(u);
  if (exists) return { ok: false, reason: '이미 존재하는 아이디입니다.' };
  if (!u || !p) return { ok: false, reason: '아이디와 비밀번호는 필수입니다.' };

  if (mode === 'vulnerable') {
    const sql = `INSERT INTO users (username, password, email, role) VALUES ('${u}', '${p}', '${e}', 'user')`;
    const queryHtml =
      `INSERT INTO users (username, password, email, role) VALUES ('${mark(u)}', '${mark(p)}', '${mark(e)}', 'user')`;
    try {
      db.prepare(sql).run();
      return { ok: true, mode, sql, queryHtml, note: '가입 완료(취약 모드). INSERT 문도 인젝션 대상이 될 수 있습니다.' };
    } catch (err) {
      return { ok: false, mode, sql, queryHtml, reason: `쿼리 오류: ${err.message}` };
    }
  }

  // 그 외 모드는 모두 안전하게 ORM/파라미터화로 처리
  const { id, sql, params } = User.create({ username: u, password: p, email: e, role: 'user' });
  return { ok: true, mode, id, sql, queryHtml: escapeHtml(sql), params, note: '가입 완료(파라미터화).' };
}

module.exports = { login, search, signup, whitelistValidate, escapeHtml };
