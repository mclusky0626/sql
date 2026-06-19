'use strict';
/*
 * 암호화 실습 위젯 — 브라우저 내장 Web Crypto API(window.crypto.subtle)로 동작.
 * 모든 연산은 클라이언트에서만 수행되며 입력값은 서버로 전송되지 않는다.
 */
(function () {
  const subtle = window.crypto && window.crypto.subtle;
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const $ = (id) => document.getElementById(id);

  if (!subtle) {
    document.querySelectorAll('.lab').forEach((el) => {
      el.innerHTML =
        '<div class="lab-title">🧪 실습</div><p class="muted">이 브라우저는 Web Crypto API를 지원하지 않거나 보안 컨텍스트(HTTPS)가 아니라 실습을 실행할 수 없습니다.</p>';
    });
    return;
  }

  // ---------- 공용 변환 ----------
  const toHex = (buf) =>
    [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
  const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const fromB64 = (s) => Uint8Array.from(atob(s.trim()), (c) => c.charCodeAt(0));
  const concat = (...arrs) => {
    const len = arrs.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(len);
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  };
  const sha = async (algo, text) => toHex(await subtle.digest(algo, enc.encode(text)));

  // ===================================================================
  // 1. 해시 플레이그라운드
  // ===================================================================
  const hashInput = $('hashInput');
  if (hashInput) {
    const refresh = async () => {
      const t = hashInput.value;
      $('h256').textContent = await sha('SHA-256', t);
      $('h512').textContent = await sha('SHA-512', t);
      $('h1').textContent = await sha('SHA-1', t);
    };
    hashInput.addEventListener('input', refresh);
    refresh();
  }

  // ===================================================================
  // 2. 솔트(salt) 데모 — 같은 비밀번호도 솔트가 다르면 해시가 달라진다
  // ===================================================================
  const saltBtn = $('saltRun');
  if (saltBtn) {
    const pbkdf2Hex = async (pw, salt, iters = 100000) => {
      const base = await subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
      const bits = await subtle.deriveBits(
        { name: 'PBKDF2', salt, iterations: iters, hash: 'SHA-256' }, base, 256);
      return toHex(bits);
    };
    saltBtn.addEventListener('click', async () => {
      const pw = $('saltPw').value || '';
      $('saltOut').hidden = false;
      // 솔트 없는 단순 해시 → 두 사용자가 동일 (레인보우 테이블에 취약)
      const plain = await sha('SHA-256', pw);
      $('saltPlainA').textContent = plain;
      $('saltPlainB').textContent = plain;
      // 솔트 + PBKDF2 → 사용자마다 다름
      const sA = window.crypto.getRandomValues(new Uint8Array(16));
      const sB = window.crypto.getRandomValues(new Uint8Array(16));
      $('saltA').textContent = toHex(sA);
      $('saltB').textContent = toHex(sB);
      $('saltHashA').textContent = await pbkdf2Hex(pw, sA);
      $('saltHashB').textContent = await pbkdf2Hex(pw, sB);
    });
  }

  // ===================================================================
  // 3. 대칭키 — AES-256-GCM (암호문 = salt | iv | ciphertext, base64)
  // ===================================================================
  const symEncBtn = $('symEnc');
  if (symEncBtn) {
    const deriveAes = async (pw, salt) => {
      const base = await subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
      return subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
        base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    };
    symEncBtn.addEventListener('click', async () => {
      const text = $('symText').value;
      const pw = $('symKey').value;
      if (!pw) return setMsg('symMsg', '키(비밀번호)를 입력하세요.', 'bad');
      const salt = window.crypto.getRandomValues(new Uint8Array(16));
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const key = await deriveAes(pw, salt);
      const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(text));
      const blob = toB64(concat(salt, iv, new Uint8Array(ct)));
      $('symCipher').value = blob;
      setMsg('symMsg', '✅ 암호화 완료 — 아래 암호문을 복호화 칸에 붙여 같은/다른 키로 시도해보세요.', 'good');
    });
    $('symDec').addEventListener('click', async () => {
      try {
        const pw = $('symKey2').value;
        const raw = fromB64($('symCipherIn').value);
        const salt = raw.slice(0, 16), iv = raw.slice(16, 28), data = raw.slice(28);
        const key = await deriveAes(pw, salt);
        const pt = await subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
        $('symPlain').value = dec.decode(pt);
        setMsg('symMsg2', '✅ 복호화 성공 — 키가 일치합니다.', 'good');
      } catch (e) {
        $('symPlain').value = '';
        setMsg('symMsg2', '❌ 복호화 실패 — 키가 틀렸거나 암호문이 손상됐습니다. (GCM 무결성 검증 실패)', 'bad');
      }
    });
    const copyBtn = $('symCopy');
    if (copyBtn) copyBtn.addEventListener('click', () => {
      $('symCipherIn').value = $('symCipher').value;
    });
  }

  // ===================================================================
  // 4. 공개키 — RSA-OAEP (공개키로 암호화 → 개인키로만 복호화)
  // ===================================================================
  let rsaKeys = null;
  const rsaGenBtn = $('rsaGen');
  if (rsaGenBtn) {
    rsaGenBtn.addEventListener('click', async () => {
      setMsg('rsaMsg', '🔧 키 쌍 생성 중…', 'muted');
      rsaKeys = await subtle.generateKey(
        { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true, ['encrypt', 'decrypt']);
      const pub = await subtle.exportKey('spki', rsaKeys.publicKey);
      const prv = await subtle.exportKey('pkcs8', rsaKeys.privateKey);
      $('rsaPub').value = toB64(pub);
      $('rsaPrv').value = toB64(prv);
      setMsg('rsaMsg', '✅ 2048비트 RSA 키 쌍 생성 완료. 공개키는 공개해도 되지만 개인키는 비밀입니다.', 'good');
    });
    $('rsaEnc').addEventListener('click', async () => {
      if (!rsaKeys) return setMsg('rsaMsg2', '먼저 키 쌍을 생성하세요.', 'bad');
      try {
        const ct = await subtle.encrypt({ name: 'RSA-OAEP' }, rsaKeys.publicKey, enc.encode($('rsaText').value));
        $('rsaCipher').value = toB64(ct);
        setMsg('rsaMsg2', '✅ 공개키로 암호화 완료 — 이제 개인키로만 열 수 있습니다.', 'good');
      } catch (e) {
        setMsg('rsaMsg2', '❌ 암호화 실패 — RSA는 짧은 데이터만 직접 암호화할 수 있습니다(약 190바이트 이하).', 'bad');
      }
    });
    $('rsaDec').addEventListener('click', async () => {
      if (!rsaKeys) return setMsg('rsaMsg2', '먼저 키 쌍을 생성하세요.', 'bad');
      try {
        const pt = await subtle.decrypt({ name: 'RSA-OAEP' }, rsaKeys.privateKey, fromB64($('rsaCipher').value));
        $('rsaPlain').value = dec.decode(pt);
        setMsg('rsaMsg2', '✅ 개인키로 복호화 성공.', 'good');
      } catch (e) {
        setMsg('rsaMsg2', '❌ 복호화 실패.', 'bad');
      }
    });
  }

  // ===================================================================
  // 5. 전자서명 — ECDSA P-256 (개인키로 서명 → 공개키로 검증)
  // ===================================================================
  let signKeys = null;
  let lastSig = null;
  const signGenBtn = $('signGen');
  if (signGenBtn) {
    const alg = { name: 'ECDSA', hash: 'SHA-256' };
    signGenBtn.addEventListener('click', async () => {
      signKeys = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      setMsg('signMsg', '✅ 서명용 키 쌍(ECDSA P-256) 생성 완료.', 'good');
      $('signSig').textContent = '';
      $('signVerify').textContent = '';
    });
    $('signDo').addEventListener('click', async () => {
      if (!signKeys) return setMsg('signMsg', '먼저 키 쌍을 생성하세요.', 'bad');
      lastSig = await subtle.sign(alg, signKeys.privateKey, enc.encode($('signMsgText').value));
      $('signSig').textContent = toB64(lastSig);
      $('signVerify').textContent = '';
      setMsg('signMsg', '✅ 개인키로 서명 생성. 아래 메시지를 바꾼 뒤 검증해보세요.', 'good');
    });
    $('signCheck').addEventListener('click', async () => {
      if (!signKeys || !lastSig) return setMsg('signMsg', '먼저 서명을 생성하세요.', 'bad');
      const ok = await subtle.verify(alg, signKeys.publicKey, lastSig, enc.encode($('signMsgText').value));
      const el = $('signVerify');
      el.textContent = ok ? '✅ 검증 성공 — 메시지가 위조되지 않았습니다.' : '❌ 검증 실패 — 메시지가 변조되었습니다!';
      el.className = 'lab-result ' + (ok ? 'good' : 'bad');
    });
  }

  function setMsg(id, text, kind) {
    const el = $(id);
    if (!el) return;
    el.textContent = text;
    el.className = 'lab-result ' + (kind || '');
  }
})();
