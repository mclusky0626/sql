'use strict';

/**
 * 아주 단순한 WAF(웹 방화벽) 시뮬레이터.
 *
 * 실제 WAF(ModSecurity, AWS WAF, Cloudflare 등)도 기본 아이디어는 같다:
 * 요청 값에서 잘 알려진 공격 시그니처(패턴)를 찾아 미리 차단한다.
 *
 * 중요한 교육 포인트(가이드에서 강조):
 *  - WAF는 "추가 방어선(defense-in-depth)"일 뿐, 근본 해결책이 아니다.
 *  - 패턴 기반이라 우회(인코딩, 주석 삽입 등)가 가능하고,
 *  - 정상 입력을 막는 오탐(false positive)도 생긴다.
 *  - 따라서 파라미터화 쿼리(코드 레벨 방어)와 반드시 함께 써야 한다.
 */

// 대표적인 SQL 인젝션 시그니처
const SIGNATURES = [
  { re: /('|%27)\s*(or|and)\s/i, name: "따옴표 뒤 OR/AND (예: ' OR )" },
  { re: /\bunion\b\s+\bselect\b/i, name: 'UNION SELECT (데이터 추출)' },
  { re: /\b(or|and)\b\s+\d+\s*=\s*\d+/i, name: '항상 참 조건 (예: OR 1=1)' },
  { re: /(--|#|\/\*)/, name: 'SQL 주석 (--, #, /*)' },
  { re: /;\s*(drop|delete|update|insert|alter)\b/i, name: '스택 쿼리 (; DROP 등)' },
  { re: /\bdrop\s+table\b/i, name: 'DROP TABLE' },
  { re: /\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(/i, name: '시간 기반 블라인드 (sleep 등)' },
  { re: /(\bselect\b.+\bfrom\b)/i, name: 'SELECT ... FROM (서브쿼리 시도)' },
];

/**
 * 주어진 입력값들을 검사한다.
 * @param {Object} fields  { 필드명: 값 } 형태
 * @returns {{blocked:boolean, reason?:string, field?:string, signature?:string}}
 */
function inspect(fields) {
  for (const [field, value] of Object.entries(fields)) {
    if (value == null) continue;
    const str = String(value);
    for (const sig of SIGNATURES) {
      if (sig.re.test(str)) {
        return {
          blocked: true,
          field,
          signature: sig.name,
          reason: `WAF 차단: '${field}' 입력에서 공격 시그니처 감지 → ${sig.name}`,
        };
      }
    }
  }
  return { blocked: false };
}

module.exports = { inspect, SIGNATURES };
