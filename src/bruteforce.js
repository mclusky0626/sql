'use strict';

/**
 * 무차별 대입(brute force) 공격 탐지기.
 *
 * 로그인 실패를 사용자명(계정) 단위로 카운트하고, 단계별로 경고/잠금 상태를 돌려준다.
 * 프런트엔드는 이 상태에 따라 로그인 화면에 시각적 경고(노랑→빨강→잠금)를 표시한다.
 *
 * 가이드에서 설명하는 실제 방어책:
 *  - 요청 속도 제한(rate limiting), 일정 횟수 실패 시 계정 잠금/지연,
 *  - CAPTCHA, 2단계 인증(2FA), 비정상 로그인 알림 등.
 */

const WINDOW_MS = 5 * 60 * 1000; // 5분 윈도우
const WARN_AT = 3;   // 노란 경고
const DANGER_AT = 5; // 빨간 경고
const LOCK_AT = 8;   // 계정 잠금

const attempts = new Map(); // key: username → { count, first, lockedUntil }

function _entry(username) {
  const now = Date.now();
  let e = attempts.get(username);
  if (!e || now - e.first > WINDOW_MS) {
    e = { count: 0, first: now, lockedUntil: 0 };
    attempts.set(username, e);
  }
  return e;
}

/** 로그인 시도 전에 호출: 현재 잠겨 있는지 확인 */
function isLocked(username) {
  const e = attempts.get(username);
  return !!(e && e.lockedUntil && Date.now() < e.lockedUntil);
}

/** 로그인 실패 기록 → 갱신된 상태 반환 */
function recordFailure(username) {
  const e = _entry(username);
  e.count += 1;
  if (e.count >= LOCK_AT) {
    e.lockedUntil = Date.now() + WINDOW_MS;
  }
  return status(username);
}

/** 로그인 성공 시 카운터 초기화 */
function recordSuccess(username) {
  attempts.delete(username);
}

/** 현재 상태 조회 */
function status(username) {
  const e = attempts.get(username) || { count: 0, lockedUntil: 0 };
  const locked = isLocked(username);
  let level = 'ok';
  if (locked) level = 'locked';
  else if (e.count >= DANGER_AT) level = 'danger';
  else if (e.count >= WARN_AT) level = 'warn';

  const remaining = Math.max(0, LOCK_AT - e.count);
  return {
    username,
    count: e.count,
    level,
    locked,
    warnAt: WARN_AT,
    dangerAt: DANGER_AT,
    lockAt: LOCK_AT,
    remainingBeforeLock: remaining,
  };
}

function resetAll() {
  attempts.clear();
}

module.exports = { isLocked, recordFailure, recordSuccess, status, resetAll, WARN_AT, DANGER_AT, LOCK_AT };
