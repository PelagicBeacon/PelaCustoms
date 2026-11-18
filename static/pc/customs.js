/*!
 * PelaCustoms 质询页 v0.1.0
 * © 2026 PelagicBeacon（PELAGIC BEACON）· MIT，见 LICENSE
 *
 * 流程：读 data-* → 可选点击关卡 → Web Worker 算 PoW → POST /__pc/verify → 刷新
 * 同源代理模式下过关就是 location.reload()，地址栏从头到尾没动过。
 */
(function () {
  'use strict';

  var el = document.getElementById('pc');
  if (!el) return;

  var D = el.dataset;
  var BASE = D.base || '';
  var LEVEL = parseInt(D.level || '1', 10) || 1;
  var PREFIX = parseInt(D.prefix || '4', 10) || 4;
  var CLICK = D.click === '1';
  var PEND = D.pend || '';
  var CHALLENGE = D.challenge || '';
  var REDIRECT = D.redirect || '/';
  var HOST = D.host || window.location.host;

  var titleEl = document.getElementById('pc-title');
  var subEl = document.getElementById('pc-sub');
  var fillEl = document.getElementById('pc-fill');
  var retryEl = document.getElementById('pc-retry');
  var hintEl = document.getElementById('pc-hint');
  var hintBtn = document.getElementById('pc-hint-btn');

  // 预估总尝试次数，只用于画进度条
  var EXPECTED = Math.pow(16, PREFIX);

  /* ------------------------------------------------------------ 状态 */
  function setState(state, title, sub) {
    el.dataset.state = state;
    if (typeof title === 'string') titleEl.textContent = title;
    if (typeof sub === 'string') subEl.textContent = sub;
  }

  function setBusy(on) {
    el.dataset.busy = on ? '1' : '0';
  }

  function setProgress(ratio) {
    var pct = Math.max(0, Math.min(1, ratio)) * 100;
    fillEl.style.width = pct.toFixed(1) + '%';
  }

  function fail(message) {
    setBusy(false);
    setState('err', '验证未通过', message || '请点击重试');
    retryEl.hidden = false;
    setProgress(0);
  }

  retryEl.addEventListener('click', function () {
    window.location.reload();
  });

  /* ------------------------------------------------------------ 环境特征 */
  function collectFeatures() {
    var nav = window.navigator || {};
    var screenObj = window.screen || {};
    var ua = nav.userAgent || '';
    var uaData = nav.userAgentData || null;
    return {
      ua: ua,
      webdriver: nav.webdriver === true,
      headless_ua: /HeadlessChrome/i.test(ua),
      chrome: typeof window.chrome !== 'undefined',
      plugins: (nav.plugins || []).length,
      languages: (nav.languages || []).length,
      hardware: nav.hardwareConcurrency || 0,
      depth: screenObj.colorDepth || 0,
      screen_w: screenObj.width || 0,
      mobile: uaData ? uaData.mobile === true : false,
      touch: nav.maxTouchPoints || 0
    };
  }

  /* ------------------------------------------------------------ PoW */
  function solvePow(onProgress) {
    return new Promise(function (resolve, reject) {
      var worker;
      try {
        worker = new Worker(BASE + '/__pc/static/customs-worker.js');
      } catch (e) {
        reject(new Error('浏览器不支持 Web Worker'));
        return;
      }
      var tried = 0;
      var done = false;

      worker.onmessage = function (ev) {
        var msg = ev.data || {};
        if (msg.type === 'progress') {
          tried += msg.tried || 0;
          onProgress(Math.min(0.92, tried / EXPECTED));
        } else if (msg.type === 'found') {
          done = true;
          worker.terminate();
          resolve(msg.nonce);
        }
      };
      worker.onerror = function () {
        if (done) return;
        done = true;
        worker.terminate();
        reject(new Error('计算线程出错'));
      };
      worker.postMessage({
        challenge: CHALLENGE, prefix: PREFIX, start: 0, step: 1
      });
    });
  }

  /* ------------------------------------------------------------ 交互 */
  var samples = [];
  var lastT = 0;
  var pointerType = 'mouse';
  var holdStart = 0;
  var holdMs = 0;
  var clicked = false;

  function resetTrack() {
    samples = [];
    lastT = 0;
  }

  function onMove(ev) {
    var now = (window.performance && performance.now) ? performance.now() : Date.now();
    if (now - lastT < 25) return;         // 节流到 25ms：和 Reeflet 一致
    lastT = now;
    if (typeof ev.pointerType === 'string' && ev.pointerType) {
      pointerType = ev.pointerType;
    }
    if (ev.isTrusted === false) pointerType = 'synthetic';
    samples.push([Math.round(ev.clientX), Math.round(ev.clientY), Math.round(now)]);
    if (samples.length > 200) samples.shift();
  }

  function onDown(ev) {
    if (ev.isTrusted === false) pointerType = 'synthetic';
    if (ev.pointerType) pointerType = ev.pointerType;
    holdStart = (window.performance && performance.now) ? performance.now() : Date.now();
  }

  function onUp() {
    if (!holdStart) return;
    var now = (window.performance && performance.now) ? performance.now() : Date.now();
    holdMs = Math.round(now - holdStart);
    holdStart = 0;
  }

  /* ------------------------------------------------------------ 主流程 */
  function run() {
    setState('working', '正在检查你的浏览器', '这一步不需要你操作');
    setBusy(true);
    setProgress(0.06);

    // 等一帧，让「正在检查」先画出来，别让用户觉得点了没反应
    window.setTimeout(function () {
      setProgress(0.12);
      solvePow(function (ratio) {
        setProgress(0.12 + ratio * 0.62);
      }).then(function (nonce) {
        setProgress(0.82);
        return submit(nonce);
      }).then(function (payload) {
        if (!payload.ok) {
          fail(payload.message || '请重试');
          return;
        }
        setBusy(false);
        setProgress(1);
        setState('ok', '验证通过', '正在返回 ' + HOST + '，请稍候…');
        window.setTimeout(finish, 420);
      }).catch(function (err) {
        fail(err && err.message ? err.message : '请重试');
      });
    }, 60);
  }

  function finish() {
    // 纵深防御：即使服务端把某个非本站地址写进了 data-redirect，
    // 这里也不跳 —— 只有同源的才允许导航，其余一律 reload 当前页。
    try {
      var target = new URL(REDIRECT || '/', window.location.href);
      if (target.origin !== window.location.origin) throw new Error('cross-origin');
      if (target.pathname !== window.location.pathname ||
          target.search !== window.location.search) {
        window.location.href = target.pathname + target.search;
        return;
      }
    } catch (e) { /* 落到下面的 reload */ }
    window.location.reload();
  }

  function submit(nonce) {
    var body = {
      pend: PEND,
      nonce: nonce,
      pointer_type: CLICK ? pointerType : 'auto',
      hold_ms: CLICK ? holdMs : 0,
      path: CLICK ? samples : [],
      features: collectFeatures()
    };
    return fetch(BASE + '/__pc/verify', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    }).then(function (res) {
      return res.json().catch(function () {
        return { ok: false, reason: 'network', message: '服务暂时不可用，请重试' };
      });
    });
  }

  /* ------------------------------------------------------------ 入口 */
  if (CLICK) {
    setState('click', '请确认你不是自动程序', '点击下方按钮继续');
    setBusy(false);
    hintEl.hidden = false;
    window.addEventListener('pointermove', onMove, { passive: true });

    hintBtn.addEventListener('pointerdown', onDown);
    hintBtn.addEventListener('pointerup', onUp);
    hintBtn.addEventListener('click', function (ev) {
      if (ev.isTrusted === false) pointerType = 'synthetic';
      if (clicked) return;
      clicked = true;
      hintEl.hidden = true;
      resetTrack();
      run();
    });
  } else {
    run();
  }
})();
