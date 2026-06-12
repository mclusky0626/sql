'use strict';

/**
 * 아주 작은 ORM(데이터 매퍼) 계층.
 *
 * Sequelize / Prisma / TypeORM 같은 실제 ORM도 핵심 원리는 동일하다:
 *   User.findOne({ where: { username, password } })
 * 처럼 "값"을 객체로 넘기면, ORM이 컬럼명만으로 SQL 골격을 만들고
 * 값은 전부 ? 자리표시자에 바인딩한다. 따라서 사용자 입력이 SQL 문법으로
 * 해석될 여지가 구조적으로 사라진다 = SQL 인젝션이 원천 차단된다.
 *
 * 이 파일은 그 동작을 투명하게 보여주기 위해 직접 구현했다.
 * (실무에서는 검증된 ORM 라이브러리를 쓰면 된다.)
 */
class Model {
  constructor(db, table, columns) {
    this.db = db;
    this.table = table;
    this.columns = columns;
  }

  /**
   * 조건 객체를 받아 안전한 파라미터화 쿼리를 만든다.
   * @param {Object} opts
   *   - where: { 컬럼: 값 }   → "컬럼 = ?" (AND 결합)
   *   - like:  { 컬럼: 부분문자열 } → "컬럼 LIKE ?" ('%값%' 로 바인딩)
   *   - columns: 조회할 컬럼 배열(기본은 전체)
   * 반환값에는 실행된 SQL 골격과 바인딩된 파라미터를 함께 담아
   * 프런트엔드 "생성된 쿼리" 패널에서 보여줄 수 있게 한다.
   */
  buildSelect({ where = {}, like = {}, columns } = {}) {
    const cols = (columns || this.columns).join(', ');
    const whereKeys = Object.keys(where);
    const likeKeys = Object.keys(like);

    // 컬럼명(식별자)은 화이트리스트로만 받는다 → 식별자 조작 방지
    for (const k of [...whereKeys, ...likeKeys, ...(columns || [])]) {
      if (!this.columns.includes(k)) throw new Error(`알 수 없는 컬럼: ${k}`);
    }

    let sql = `SELECT ${cols} FROM ${this.table}`;
    const params = [];
    const clauses = [];
    for (const k of whereKeys) {
      clauses.push(`${k} = ?`);
      params.push(where[k]); // 값은 항상 ? 에 바인딩 (절대 문자열로 붙이지 않음)
    }
    for (const k of likeKeys) {
      clauses.push(`${k} LIKE ?`);
      params.push(`%${like[k]}%`);
    }
    if (clauses.length) sql += ` WHERE ${clauses.join(' AND ')}`;
    return { sql, params };
  }

  find(opts) {
    const { sql, params } = this.buildSelect(opts);
    const rows = this.db.prepare(sql).all(...params);
    return { rows, sql, params };
  }

  findAll(where) {
    return this.find({ where });
  }

  findOne(where, columns) {
    const { sql, params } = this.buildSelect({ where, columns });
    const row = this.db.prepare(sql).get(...params);
    return { row: row || null, sql, params };
  }

  create(values) {
    const keys = Object.keys(values);
    for (const k of keys) {
      if (!this.columns.includes(k)) throw new Error(`알 수 없는 컬럼: ${k}`);
    }
    const placeholders = keys.map(() => '?').join(', ');
    const sql = `INSERT INTO ${this.table} (${keys.join(', ')}) VALUES (${placeholders})`;
    const params = keys.map((k) => values[k]);
    const info = this.db.prepare(sql).run(...params);
    return { id: info.lastInsertRowid, sql, params };
  }
}

function models(db) {
  return {
    User: new Model(db, 'users', ['id', 'username', 'password', 'email', 'role', 'secret']),
    Post: new Model(db, 'posts', ['id', 'title', 'body', 'author', 'visible']),
  };
}

module.exports = { Model, models };
