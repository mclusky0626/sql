'use strict';

// Node.js 22.5+ 내장 SQLite 모듈 (별도 네이티브 빌드가 필요 없음)
const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');

// 데모용이므로 메모리 DB가 아닌 파일 DB를 쓰되, 서버 시작 시 항상 새로 시드한다.
const DB_PATH = path.join(__dirname, '..', 'data', 'app.db');

let db;

/**
 * 데이터베이스를 열고 스키마 + 시드 데이터를 생성한다.
 * 교육용 데모라 매 실행마다 깨끗한 상태로 초기화한다.
 */
function init() {
  const fs = require('node:fs');
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  db = new DatabaseSync(DB_PATH);
  reset();
  return db;
}

function getDb() {
  if (!db) init();
  return db;
}

/**
 * 스키마를 다시 만들고 시드 데이터를 채운다. (데모 반복을 위해 /api/reset 에서도 호출)
 *
 * 주의: 비밀번호를 평문으로 저장하는 것은 의도적으로 "나쁜 예시"다.
 * 인젝션으로 users 테이블이 통째로 유출됐을 때 피해가 얼마나 큰지 보여주기 위함이며,
 * 실제 서비스에서는 반드시 bcrypt/argon2 같은 해시로 저장해야 한다. (가이드에서 설명)
 */
function reset() {
  db.exec(`
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS posts;

    CREATE TABLE users (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email    TEXT,
      role     TEXT NOT NULL DEFAULT 'user',
      secret   TEXT
    );

    CREATE TABLE posts (
      id      INTEGER PRIMARY KEY AUTOINCREMENT,
      title   TEXT NOT NULL,
      body    TEXT,
      author  TEXT,
      visible INTEGER NOT NULL DEFAULT 1
    );
  `);

  const insertUser = db.prepare(
    'INSERT INTO users (username, password, email, role, secret) VALUES (?, ?, ?, ?, ?)'
  );
  const seedUsers = [
    ['admin', 'Adm!n_2024#', 'admin@dummy-corp.kr', 'admin', '관리자 마스터 키: MK-9931-ALPHA'],
    ['minji', 'sunflower7', 'minji@dummy-corp.kr', 'user', '주민번호: 990101-2******'],
    ['jiwoo', 'qwerty123', 'jiwoo@dummy-corp.kr', 'user', '카드번호: 5412-****-****-9921'],
    ['steve', 'password1', 'steve@dummy-corp.kr', 'user', '내부 결재 비밀번호: hr-0440'],
    ['guest', 'guest', 'guest@dummy-corp.kr', 'user', '없음'],
  ];
  for (const u of seedUsers) insertUser.run(...u);

  const insertPost = db.prepare(
    'INSERT INTO posts (title, body, author, visible) VALUES (?, ?, ?, ?)'
  );
  const seedPosts = [
    ['신규 회원 이벤트 안내', '가입하시면 포인트를 드립니다.', 'admin', 1],
    ['시스템 점검 공지', '6월 20일 새벽 2시~4시 점검 예정입니다.', 'admin', 1],
    ['여름 휴가 안내', '8월 첫째 주 단축 운영합니다.', 'minji', 1],
    ['[비공개] 내부 감사 일정', '외부에 노출되면 안 되는 비공개 게시글입니다.', 'admin', 0],
    ['자주 묻는 질문(FAQ)', '비밀번호 분실 시 고객센터로 문의하세요.', 'jiwoo', 1],
  ];
  for (const p of seedPosts) insertPost.run(...p);
}

module.exports = { init, getDb, reset, DB_PATH };
