import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { SharedArray } from 'k6/data';
import { Trend, Rate, Counter } from 'k6/metrics';
import exec from 'k6/execution';

const BASE_URL = 'http://localhost:3000';

// --------------------
// Ayarlanabilir flood parametreleri
// --------------------
const SEARCH_HEAVY_RATIO = 0.75; // %75 search ağırlıklı
const AUTH_HEAVY_RATIO = 0.25;   // %25 login ağırlıklı
const MIN_BURST = 2;
const MAX_BURST = 4;

// --------------------
// Custom metrics
// --------------------
const floodLoginDuration = new Trend('flood_login_duration', true);
const floodSearchDuration = new Trend('flood_search_duration', true);

const floodLoginSuccess = new Rate('flood_login_success');
const floodSearchSuccess = new Rate('flood_search_success');
const floodTokenIssued = new Rate('flood_token_issued');

const floodLoginRequests = new Counter('flood_login_requests');
const floodSearchRequests = new Counter('flood_search_requests');
const floodCompletedBursts = new Counter('flood_completed_bursts');

// --------------------
// Test hesapları
// --------------------
const users = new SharedArray('users', function () {
  return [
    { email: 'levintolstoy@gmail.com', password: '123456' },
    { email: 'annakarenina@gmail.com', password: '1111' },
    { email: 'adrien@gmail.com', password: '2222' },
    { email: 'maya@gmail.com', password: '3333' },
    { email: 'beyza@gmail.com', password: '4444' },
    { email: 'user6@gmail.com', password: '5555' },
    { email: 'user7@gmail.com', password: '6666' },
    { email: 'user8@gmail.com', password: '7777' },
  ];
});

// --------------------
// Bot user-agent havuzu
// DİKKAT: request bazında değil, VU bazında sabitlenecek
// --------------------
const attackerAgents = new SharedArray('attackerAgents', function () {
  return [
    'FloodBot/1.0',
    'FloodBot/1.1',
    'AggressiveClient/2.0',
  ];
});

// --------------------
// Ağır arama terimleri
// --------------------
const heavyTerms = new SharedArray('heavyTerms', function () {
  return [
    'güvenlik',
    'veri',
    'analiz',
    'koruma',
    'tez',
    'fingerprint',
    'saldırı',
  ];
});

export const options = {
  scenarios: {
    http_flood: {
      executor: 'ramping-arrival-rate',
      exec: 'httpFloodFlow',
      startRate: 2,
      timeUnit: '1s',
      preAllocatedVUs: 30,
      maxVUs: 80,
      stages: [
        { target: 4, duration: '30s' },
        { target: 8, duration: '60s' },
        { target: 12, duration: '60s' },
        { target: 0, duration: '20s' },
      ],
      tags: { trafficLabel: 'http_flood' },
    },
  },

  thresholds: {
    // Flood testinde 500/429 görmek olağan olabilir.
    // O yüzden burada çok katı başarı threshold'u koymuyoruz.
    'iterations{scenario:http_flood}': ['count>0'],
    'flood_login_duration{trafficLabel:http_flood}': ['p(95)<6000'],
    'flood_search_duration{trafficLabel:http_flood}': ['p(95)<4000'],
  },
};

function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function stableAttackerProfile() {
  const vuId = exec.vu.idInTest || 1;

  return {
    ip: `10.10.1.${(vuId % 253) + 1}`,
    userAgent: attackerAgents[(vuId - 1) % attackerAgents.length],
    user: users[(vuId - 1) % users.length],
  };
}

function buildBaseHeaders(profile) {
  return {
    'Content-Type': 'application/json',
    'x-simulation-label': 'http_flood',
    'x-test-client-ip': profile.ip,
    'User-Agent': profile.userAgent,
  };
}

function pickFlowType() {
  return Math.random() < SEARCH_HEAVY_RATIO ? 'search_heavy' : 'auth_heavy';
}

function pickBurstSize() {
  return Math.floor(Math.random() * (MAX_BURST - MIN_BURST + 1)) + MIN_BURST;
}

function parseToken(loginRes) {
  try {
    return loginRes.json('accessToken');
  } catch (_) {
    return null;
  }
}

function recordLoginMetric(loginRes) {
  floodLoginDuration.add(loginRes.timings.duration, {
    trafficLabel: 'http_flood',
  });

  const loginOk = loginRes.status === 200 || loginRes.status === 201;
  floodLoginSuccess.add(loginOk ? 1 : 0, { trafficLabel: 'http_flood' });

  check(loginRes, {
    'flood login response known': (r) =>
      [200, 201, 400, 401, 403, 429, 500].includes(r.status),
  });

  return loginOk;
}

function recordSearchMetric(searchRes) {
  floodSearchDuration.add(searchRes.timings.duration, {
    trafficLabel: 'http_flood',
  });

  const searchOk = searchRes.status === 200;
  floodSearchSuccess.add(searchOk ? 1 : 0, { trafficLabel: 'http_flood' });

  check(searchRes, {
    'flood search response known': (r) =>
      [200, 400, 401, 403, 429, 500].includes(r.status),
  });

  return searchOk;
}

export function httpFloodFlow() {
  const profile = stableAttackerProfile();
  const headers = buildBaseHeaders(profile);
  const flowType = pickFlowType();

  group('HTTP Flood Session', function () {
    floodLoginRequests.add(1, { trafficLabel: 'http_flood' });

    const loginRes = http.post(
      `${BASE_URL}/auth/login`,
      JSON.stringify(profile.user),
      { headers }
    );

    const loginOk = recordLoginMetric(loginRes);

    if (!loginOk) {
      floodTokenIssued.add(0, { trafficLabel: 'http_flood' });
      return;
    }

    const token = parseToken(loginRes);
    const hasToken = !!token;

    floodTokenIssued.add(hasToken ? 1 : 0, { trafficLabel: 'http_flood' });

    if (!token) {
      return;
    }

    // Auth-heavy alt tip: sadece login baskısı bırakıp çık
    if (flowType === 'auth_heavy') {
      return;
    }

    const authParams = {
      headers: {
        ...headers,
        Authorization: `Bearer ${token}`,
      },
    };

    const burstSize = pickBurstSize();

    for (let i = 0; i < burstSize; i++) {
      floodSearchRequests.add(1, { trafficLabel: 'http_flood' });

      const term = randomItem(heavyTerms);
      const page = (i % 5) + 1;
      const limit = 10;

      const searchRes = http.get(
        `${BASE_URL}/user/search?q=${encodeURIComponent(term)}&page=${page}&limit=${limit}`,
        authParams
      );

      recordSearchMetric(searchRes);

      // Tamamen sıfır bekleme yerine çok küçük jitter:
      // Hem istemci davranışı sabit kalsın, hem aynı ms'e aşırı yığılma olmasın
      if (i < burstSize - 1) {
        sleep(Math.random() * 0.12 + 0.03); // 30ms - 150ms
      }
    }

    floodCompletedBursts.add(1, { trafficLabel: 'http_flood' });
  });
 }