import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { SharedArray } from 'k6/data';
import { Trend, Rate, Counter } from 'k6/metrics';
import exec from 'k6/execution';

const BASE_URL = 'http://localhost:3000';

// =====================================================================
// CUSTOM METRICS
// =====================================================================
const loginDuration    = new Trend('app_login_duration', true);
const profileDuration  = new Trend('app_profile_duration', true);
const searchDuration   = new Trend('app_search_duration', true);
const logoutDuration   = new Trend('app_logout_duration', true);

const logicalFailures   = new Rate('app_logical_failures');
const startedSessions   = new Counter('app_started_sessions');
const completedSessions = new Counter('app_completed_sessions');
const abortedSessions   = new Counter('app_aborted_sessions');
const bouncedSessions   = new Counter('app_bounced_sessions');

// =====================================================================
// SEEDED USERS (15 users for peak 15 VUs)
// =====================================================================
const users = new SharedArray('users', function () {
  return [
    { email: 'levintolstoy@gmail.com',  password: '123456' },
    { email: 'annakarenina@gmail.com',  password: '1111'   },
    { email: 'adrien@gmail.com',        password: '2222'   },
    { email: 'maya@gmail.com',          password: '3333'   },
    { email: 'beyza@gmail.com',         password: '4444'   },
    { email: 'user6@gmail.com',         password: '5555'   },
    { email: 'user7@gmail.com',         password: '6666'   },
    { email: 'user8@gmail.com',         password: '7777'   },
    { email: 'user9@gmail.com',         password: '8888'   },
    { email: 'user10@gmail.com',        password: '9999'   },
    { email: 'user11@gmail.com',        password: '101010' },
    { email: 'user12@gmail.com',        password: '121212' },
    { email: 'user13@gmail.com',        password: '131313' },
    { email: 'user14@gmail.com',        password: '141414' },
    { email: 'user15@gmail.com',        password: '151515' },
  ];
});

// =====================================================================
// USER-AGENT HAVUZU
// StatCounter 2024 global browser market share'ine yakın bir dağılım:
// Chrome ~%62, Safari ~%20, Edge ~%5, Firefox ~%3, Mobile Safari + Samsung ~%10
// Havuzdan seçim `pickWeighted()` ile yapılıyor; böylece entropy analizi
// gerçek dünya fingerprint dağılımını yansıtır.
// =====================================================================
const userAgents = new SharedArray('userAgents', function () {
  return [
    // Desktop Chrome - en yaygın
    { ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36', w: 35 },
    { ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36', w: 15 },
    // Desktop Safari
    { ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15', w: 8 },
    // Edge
    { ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0', w: 5 },
    // Firefox
    { ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0', w: 3 },
    // Mobile Safari (iPhone)
    { ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1', w: 18 },
    // Android Chrome
    { ua: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36', w: 10 },
    // Samsung Internet
    { ua: 'Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36', w: 6 },
  ];
});

// =====================================================================
// ACCEPT-LANGUAGE & ACCEPT-ENCODING havuzları
// Entropy analizinde tek başına UA değil, (UA + Lang + Enc) tuple'ı
// istemci fingerprint'i olarak kullanılabilsin diye ayrıldı.
// =====================================================================
const acceptLangs = new SharedArray('acceptLangs', function () {
  return [
    'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
    'tr,en-US;q=0.9,en;q=0.8',
    'en-US,en;q=0.9',
    'en-GB,en;q=0.9,tr;q=0.8',
    'tr-TR,tr;q=0.9',
  ];
});

const acceptEncs = new SharedArray('acceptEncs', function () {
  return [
    'gzip, deflate, br',
    'gzip, deflate, br, zstd',
    'gzip, deflate',
  ];
});

// =====================================================================
// IP HAVUZU
// İki farklı /24 subnet kullanılıyor. Low-slow botlar tek subnet'te
// sabit IP kullandığı için entropy karşılaştırmasında ayrışma belirgin.
// x-test-client-ip → middleware → trafficLabel ile RequestLog'a yazılır.
// =====================================================================
const ipPool = new SharedArray('ipPool', function () {
  const pool = [];
  for (let i = 1; i <= 15; i++) pool.push(`192.168.1.${i}`);
  for (let i = 1; i <= 10; i++) pool.push(`10.0.0.${i}`);
  return pool;
});

// =====================================================================
// SEARCH TERM HAVUZU - Zipf dağılımı ile kullanılacak
// Sıralama popülerliğe göre yapıldı: index 0 en popüler.
// Zipf α=1.0 ile: top-3 ≈ %55, top-5 ≈ %70, kuyruk ≈ %30
// Yandex ve Lucene search log analizlerinden tipik değerler.
// =====================================================================
const searchTerms = new SharedArray('searchTerms', function () {
  return [
    'güvenlik', 'veri', 'analiz', 'yapay-zeka', 'saldırı',
    'koruma', 'tez', 'fingerprint', 'performans', 'log',
    'authentication', 'token', 'middleware', 'entropy', 'ddos',
  ];
});

// =====================================================================
// MARKOV CHAIN - sayfa geçiş olasılıkları
// Her satır: "şu an burdayım, sonraki nereye?" olasılık dağılımı.
// exit = oturumu bitir. Gerçek web analytics clickstream'lerinden fit.
// =====================================================================
const transitionMatrix = {
  start:   { profile: 0.30, search: 0.55, exit: 0.15 },
  profile: { search:  0.55, profile: 0.10, exit: 0.35 },
  search:  { search:  0.45, profile: 0.30, exit: 0.25 },
};

// =====================================================================
// OPTIONS
// =====================================================================
export const options = {
  scenarios: {
    legit_users: {
      executor: 'ramping-vus',
      exec: 'legitimateUserFlow',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 5  },
        { duration: '2m',  target: 15 },
        { duration: '30s', target: 0  },
      ],
      gracefulRampDown: '10s',
      tags: { trafficLabel: 'normal_user' },
    },
  },
  thresholds: {
    'http_req_duration{trafficLabel:normal_user}':    ['p(95)<1200'],
    'http_req_failed{trafficLabel:normal_user}':      ['rate<0.10'],
    'app_logical_failures{trafficLabel:normal_user}': ['rate<0.05'],
    'app_login_duration{trafficLabel:normal_user}':   ['p(95)<2000'],
    'app_search_duration{trafficLabel:normal_user}':  ['p(95)<1200'],
  },
};

// =====================================================================
// PER-VU STATE
// =====================================================================
let vuState = null;

// =====================================================================
// DISTRIBUTION HELPERS
// =====================================================================

// Box-Muller ile standart normal örnek
function standardNormal() {
  const u1 = Math.max(Math.random(), 1e-9);
  const u2 = Math.random();
  return Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
}

// Log-normal think time (Barford & Crovella SURGE + Arlitt-Williamson)
// μ=1.2, σ=0.8 parametreleri:
//   medyan ≈ 3.3s, mean ≈ 4.5s, p95 ≈ 12s, p99 ≈ 25s
// Klasik web browsing think time dağılımına uyuyor.
function thinkLogNormal(muLog = 1.2, sigmaLog = 0.8, minS = 0.3, maxS = 45) {
  const z = standardNormal();
  const s = Math.exp(muLog + sigmaLog * z);
  sleep(Math.min(Math.max(s, minS), maxS));
}

// Kısa etkileşim içi gecikme (aynı form içinde, butonlar arası)
function thinkShort() {
  thinkLogNormal(0.3, 0.6, 0.2, 5);   // medyan ~1.3s
}

// Orta gecikme (sayfalar arası)
function thinkMedium() {
  thinkLogNormal(1.2, 0.8, 0.5, 30);  // medyan ~3.3s
}

// Uzun gecikme (okumak, düşünmek)
function thinkLong() {
  thinkLogNormal(2.0, 0.9, 1.0, 60);  // medyan ~7.4s
}

// Zipf örnekleyici - index döndürür (0-based)
function zipfSample(n, alpha = 1.0) {
  // Basit rejection-free ters dönüşüm yaklaşımı
  const u = Math.max(Math.random(), 1e-9);
  const idx = Math.floor(Math.pow(u, -1 / alpha)) - 1;
  return Math.min(idx, n - 1);
}

// Ağırlıklı seçim (UA pool için)
function pickWeighted(items) {
  const total = items.reduce((s, it) => s + it.w, 0);
  let r = Math.random() * total;
  for (const it of items) {
    r -= it.w;
    if (r <= 0) return it;
  }
  return items[items.length - 1];
}

function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function parseAccessToken(res) {
  try   { return res.json('accessToken'); }
  catch { return null; }
}

// =====================================================================
// SESSION LENGTH (pages per session)
// %45 bounce (tek sayfa), kalanı geometric (mean ~5-6).
// Modern web analytics ortalamalarına uyuyor.
// =====================================================================
function sessionLength() {
  if (Math.random() < 0.45) return 1;           // bounce
  let n = 2;
  while (Math.random() < 0.72 && n < 15) n++;   // geometric tail
  return n;
}

// =====================================================================
// VU INIT
// =====================================================================
function getVuState() {
  if (vuState !== null) return vuState;

  const vuNumber  = exec.vu.idInTest || 1;
  const userIndex = (vuNumber - 1) % users.length;

  // VU→IP deterministik mapping (gerçek kullanıcı IP değiştirmez,
  // aynı NAT/mobil ağda sabit kalır). Bu davranışı bilerek koruyoruz.
  const ipIndex   = (vuNumber - 1) % ipPool.length;

  // UA seçimi market share ağırlıklı (gerçek dünya entropy'si)
  const uaPick    = pickWeighted(userAgents);
  const lang      = randomItem(acceptLangs);
  const enc       = randomItem(acceptEncs);

  vuState = {
    vuNumber,
    user:      users[userIndex],
    userAgent: uaPick.ua,
    acceptLanguage: lang,
    acceptEncoding: enc,
    fakeIp:    ipPool[ipIndex],
    accessToken:       null,
    pagesRemaining:    sessionLength(),
    lastPageState:     'start',
  };

  return vuState;
}

function buildBaseHeaders(state) {
  return {
    'Content-Type':     'application/json',
    'Accept':           'application/json, text/plain, */*',
    'Accept-Language':  state.acceptLanguage,
    'Accept-Encoding':  state.acceptEncoding,
    // x-simulation-label → middleware tarafından okunarak
    // RequestLog.trafficLabel alanına yazılır. Ground truth.
    'x-simulation-label': 'normal_user',
    'User-Agent':       state.userAgent,
    'x-test-client-ip': state.fakeIp,
  };
}

function buildAuthParams(state, referer = null) {
  const headers = {
    ...buildBaseHeaders(state),
    Authorization: `Bearer ${state.accessToken}`,
  };
  if (referer) headers['Referer'] = referer;
  return { headers };
}

// =====================================================================
// MARKOV CHAIN GEÇİŞİ
// =====================================================================
function nextState(current) {
  const dist = transitionMatrix[current] || transitionMatrix.start;
  const r = Math.random();
  let acc = 0;
  for (const [target, p] of Object.entries(dist)) {
    acc += p;
    if (r < acc) return target;
  }
  return 'exit';
}

// =====================================================================
// SEARCH TERM / BAD INPUT
// =====================================================================
function pickSearchTerm() {
  const idx = zipfSample(searchTerms.length, 1.0);
  return searchTerms[idx];
}

function randomGarbage() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789?!@#$%';
  const len   = Math.floor(Math.random() * 5) + 1;
  let result  = '';
  for (let i = 0; i < len; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

// Toplam bad-input oranı: %2 (gerçek web analytics ortalamasına uygun)
function maybeBadSearchTerm() {
  let term = pickSearchTerm();
  const r  = Math.random();
  if      (r < 0.005) term = '   ';
  else if (r < 0.010) term = 'a';
  else if (r < 0.015) term = '???';
  else if (r < 0.020) term = randomGarbage();
  return term;
}

function isGarbage(term) {
  const t = term.trim();
  if (t === '')      return true;
  if (t.length === 1) return true;
  return !/^[a-zA-Z0-9ğüşöçıİĞÜŞÖÇ\s-]+$/.test(t);
}

function clearToken(state) {
  state.accessToken    = null;
  state.pagesRemaining = sessionLength();
  state.lastPageState  = 'start';
}

// =====================================================================
// AUTH
// =====================================================================
function ensureAuthenticated(state) {
  if (state.accessToken) return true;

  startedSessions.add(1, { trafficLabel: 'normal_user' });

  const loginRes = http.post(
    `${BASE_URL}/auth/login`,
    JSON.stringify(state.user),
    { headers: buildBaseHeaders(state) },
  );

  loginDuration.add(loginRes.timings.duration, { trafficLabel: 'normal_user' });

  const loginOk = check(loginRes, {
    'login response valid': (r) => [200, 201].includes(r.status),
  });

  if (!loginOk) {
    logicalFailures.add(1, { trafficLabel: 'normal_user' });
    abortedSessions.add(1, { trafficLabel: 'normal_user' });
    clearToken(state);
    return false;
  }

  const token = parseAccessToken(loginRes);
  if (!token) {
    logicalFailures.add(1, { trafficLabel: 'normal_user' });
    abortedSessions.add(1, { trafficLabel: 'normal_user' });
    clearToken(state);
    return false;
  }

  state.accessToken = token;
  thinkMedium();  // login başarılı → ilk aksiyon arası doğal gecikme
  return true;
}

// =====================================================================
// ACTIONS - her action 401/403 alırsa kullanıcı login sayfasına
// yönlendirilir; bu insan tepki süresi için thinkMedium ekleniyor.
// =====================================================================
function doProfileRequest(state) {
  if (!ensureAuthenticated(state)) return false;

  const referer = `${BASE_URL}/dashboard`;
  let res = http.get(`${BASE_URL}/user/profile`, buildAuthParams(state, referer));
  profileDuration.add(res.timings.duration, { trafficLabel: 'normal_user' });

  if ([401, 403].includes(res.status)) {
    clearToken(state);
    thinkMedium();  // redirect → login → insan tepkisi
    if (!ensureAuthenticated(state)) return false;
    res = http.get(`${BASE_URL}/user/profile`, buildAuthParams(state, referer));
    profileDuration.add(res.timings.duration, { trafficLabel: 'normal_user' });
  }

  const ok = check(res, { 'profile response valid': (r) => r.status === 200 });
  if (!ok) logicalFailures.add(1, { trafficLabel: 'normal_user' });
  return ok;
}

function doSearchRequest(state, maxPage = 5) {
  if (!ensureAuthenticated(state)) return false;

  const page     = Math.floor(Math.random() * maxPage) + 1;
  const term     = maybeBadSearchTerm();
  const badInput = isGarbage(term);
  const url      = `${BASE_URL}/user/search?q=${encodeURIComponent(term)}&page=${page}&limit=10`;
  const referer  = `${BASE_URL}/search`;

  let res = http.get(url, buildAuthParams(state, referer));
  searchDuration.add(res.timings.duration, { trafficLabel: 'normal_user' });

  if ([401, 403].includes(res.status)) {
    clearToken(state);
    thinkMedium();
    if (!ensureAuthenticated(state)) return false;
    res = http.get(url, buildAuthParams(state, referer));
    searchDuration.add(res.timings.duration, { trafficLabel: 'normal_user' });
  }

  const ok = check(res, {
    'search response valid': (r) =>
      badInput ? [200, 400, 422].includes(r.status) : r.status === 200,
  });
  if (!ok) logicalFailures.add(1, { trafficLabel: 'normal_user' });
  return ok;
}

function doLogoutRequest(state) {
  if (!state.accessToken) return true;

  const res = http.post(`${BASE_URL}/auth/logout`, null, buildAuthParams(state));
  logoutDuration.add(res.timings.duration, { trafficLabel: 'normal_user' });

  const ok = check(res, {
    'logout response valid': (r) => [200, 201, 204, 401, 403].includes(r.status),
  });
  if (!ok) logicalFailures.add(1, { trafficLabel: 'normal_user' });
  clearToken(state);
  return ok;
}

// =====================================================================
// MAIN FLOW
// - Markov zinciri ile sayfa geçişleri
// - pagesRemaining sayacı ile oturum uzunluğu kontrolü
// - explicit logout oranı %8 (gerçek web analytics)
// =====================================================================
export function legitimateUserFlow() {
  const state = getVuState();

  group('User Session', function () {
    // Oturum başlarken kısa bir "landing" gecikmesi
    thinkShort();

    while (state.pagesRemaining > 0) {
      const next = nextState(state.lastPageState);

      if (next === 'exit') break;

      let actionOk = false;
      if (next === 'profile') {
        actionOk = doProfileRequest(state);
      } else if (next === 'search') {
        actionOk = doSearchRequest(state, 5);
      }

      if (!actionOk) {
        // Kullanıcı hata aldı → kısa bir tereddüt, sonra oturumu bitir
        thinkMedium();
        break;
      }

      state.lastPageState = next;
      state.pagesRemaining -= 1;

      // Sayfalar arası think-time (log-normal)
      // Profile sayfası genelde daha uzun okunur, search'ten search'e
      // daha hızlı geçilir; ayrıştırılmış gecikme.
      if (next === 'profile') {
        thinkLong();
      } else {
        thinkMedium();
      }
    }

    // Oturum bitişi
    if (state.lastPageState === 'start') {
      // Hiç sayfa açılmadı - landing sonrası hemen çıkış
      bouncedSessions.add(1, { trafficLabel: 'normal_user' });
    }

    // Explicit logout oranı %8 (gerçek dünya: kullanıcıların büyük
    // çoğunluğu sekmeyi kapatır, az kısmı logout'a basar)
    const doesExplicitLogout = Math.random() < 0.08;
    if (doesExplicitLogout && state.accessToken) {
      thinkMedium();
      doLogoutRequest(state);
    } else {
      clearToken(state);
    }

    completedSessions.add(1, { trafficLabel: 'normal_user' });

    // Bir sonraki oturuma kadar beklenen süre.
    // Test süresi 3 dk olduğu için üst sınır kısa tutuldu; bir sonraki
    // VU iterasyonunda yeni bir "kullanıcı ziyareti" başlayacak.
    // Gerçek inter-session gap heavy-tailed (Pareto α≈1.2); burada
    // pratik olması için log-normal kullanıldı.
    thinkLogNormal(2.5, 0.7, 5, 40);
  });
}