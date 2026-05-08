import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { SharedArray } from 'k6/data';
import { Trend, Rate, Counter } from 'k6/metrics';
import exec from 'k6/execution';

const BASE_URL = 'http://localhost:3000';

// --------------------
// Ayarlanabilir low-slow parametreleri
// --------------------
const SEARCH_RATIO = 0.80;            // %80 search, %20 profile
const RELOGIN_EVERY_N_STEPS = 30;     // Belirli aralıkla token yenilemeden tekrar login
const MIN_JITTER = 0.02;              // 20ms
const MAX_JITTER = 0.09;              // 90ms

// --------------------
// Metrics
// --------------------
const lowSlowLoginDuration = new Trend('low_slow_login_duration', true);
const lowSlowStepDuration = new Trend('low_slow_step_duration', true);

const lowSlowLoginSuccess = new Rate('low_slow_login_success');
const lowSlowStepSuccess = new Rate('low_slow_step_success');

const lowSlowLogins = new Counter('low_slow_logins');
const lowSlowSteps = new Counter('low_slow_steps');
const lowSlowSearches = new Counter('low_slow_searches');
const lowSlowProfiles = new Counter('low_slow_profiles');
const lowSlowReauths = new Counter('low_slow_reauths');

export const options = {
  scenarios: {
    low_slow_bot: {
      executor: 'constant-vus',
      exec: 'lowSlowBotFlow',
      vus: 3,
      duration: '4m',
      tags: { trafficLabel: 'low_slow_bot' },
    },
  },
  thresholds: {
    'iterations{scenario:low_slow_bot}': ['count>0'],
    'low_slow_login_duration{trafficLabel:low_slow_bot}': ['p(95)<6000'],
    'low_slow_step_duration{trafficLabel:low_slow_bot}': ['p(95)<5000'],
  },
};

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

const slowAgents = new SharedArray('slowAgents', function () {
  return [
    'PeriodicStealthBot/1.0',
    'LowRateClient/1.2',
    'SlowProbe/2.0',
  ];
});

// Çok dar query havuzu: düşük entropy
const steadyTerms = new SharedArray('steadyTerms', function () {
  return ['veri', 'analiz', 'güvenlik'];
});

// VU başına durum
const vuStates = {};

function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function stableBotProfile() {
  const vuId = exec.vu.idInTest || 1;

  return {
    vuId,
    ip: `10.20.1.${(vuId % 253) + 1}`,
    userAgent: slowAgents[(vuId - 1) % slowAgents.length],
    user: users[(vuId - 1) % users.length],

    // Her botun kendi sabit kadansı olsun; hepsi aynı saniyede vurmasın
    cadenceBase: 2.20 + (((vuId - 1) % 4) * 0.10), // 2.20, 2.30, 2.40, 2.50
  };
}

function getVuState() {
  const vuId = exec.vu.idInTest || 1;

  if (!vuStates[vuId]) {
    vuStates[vuId] = {
      token: null,
      stepsSinceLogin: 0,
    };
  }

  return vuStates[vuId];
}

function buildBaseHeaders(profile) {
  return {
    'Content-Type': 'application/json',
    'x-simulation-label': 'low_slow_bot',
    'x-test-client-ip': profile.ip,
    'User-Agent': profile.userAgent,
  };
}

function buildAuthParams(headers, token) {
  return {
    headers: {
      ...headers,
      Authorization: `Bearer ${token}`,
    },
  };
}

function parseToken(loginRes) {
  try {
    return loginRes.json('accessToken');
  } catch (_) {
    return null;
  }
}

function cadenceSleep(profile) {
  const jitter = Math.random() * (MAX_JITTER - MIN_JITTER) + MIN_JITTER;
  sleep(profile.cadenceBase + jitter);
}

function doLogin(profile, state, headers) {
  lowSlowLogins.add(1, { trafficLabel: 'low_slow_bot' });

  const loginRes = http.post(
    `${BASE_URL}/auth/login`,
    JSON.stringify(profile.user),
    { headers }
  );

  lowSlowLoginDuration.add(loginRes.timings.duration, {
    trafficLabel: 'low_slow_bot',
  });

  const loginOk = check(loginRes, {
    'low-slow login response known': (r) =>
      [200, 201, 400, 401, 403, 429, 500].includes(r.status),
  });

  const success = loginRes.status === 200 || loginRes.status === 201;
  lowSlowLoginSuccess.add(success ? 1 : 0, { trafficLabel: 'low_slow_bot' });

  if (!loginOk || !success) {
    state.token = null;
    state.stepsSinceLogin = 0;
    return false;
  }

  const token = parseToken(loginRes);

  if (!token) {
    state.token = null;
    state.stepsSinceLogin = 0;
    return false;
  }

  state.token = token;
  state.stepsSinceLogin = 0;
  return true;
}

function doProfile(headersWithAuth) {
  lowSlowProfiles.add(1, { trafficLabel: 'low_slow_bot' });
  lowSlowSteps.add(1, { trafficLabel: 'low_slow_bot' });

  const res = http.get(`${BASE_URL}/user/profile`, headersWithAuth);

  lowSlowStepDuration.add(res.timings.duration, {
    trafficLabel: 'low_slow_bot',
  });

  const ok = check(res, {
    'low-slow profile response known': (r) =>
      [200, 401, 403, 429, 500].includes(r.status),
  });

  const success = res.status === 200;
  lowSlowStepSuccess.add(success ? 1 : 0, { trafficLabel: 'low_slow_bot' });

  return { ok, success, res };
}

function doSearch(headersWithAuth) {
  lowSlowSearches.add(1, { trafficLabel: 'low_slow_bot' });
  lowSlowSteps.add(1, { trafficLabel: 'low_slow_bot' });

  const term = randomItem(steadyTerms);

  // Çok dar sayfa aralığı: davranış daha makineleşmiş görünsün
  const page = Math.random() < 0.75 ? 1 : 2;
  const limit = 10;

  const res = http.get(
    `${BASE_URL}/user/search?q=${encodeURIComponent(term)}&page=${page}&limit=${limit}`,
    headersWithAuth
  );

  lowSlowStepDuration.add(res.timings.duration, {
    trafficLabel: 'low_slow_bot',
  });

  const ok = check(res, {
    'low-slow search response known': (r) =>
      [200, 401, 403, 429, 500].includes(r.status),
  });

  const success = res.status === 200;
  lowSlowStepSuccess.add(success ? 1 : 0, { trafficLabel: 'low_slow_bot' });

  return { ok, success, res };
}

export function lowSlowBotFlow() {
  const profile = stableBotProfile();
  const state = getVuState();
  const headers = buildBaseHeaders(profile);

  group('Low Slow Bot Session', function () {
    const needLogin =
      !state.token || state.stepsSinceLogin >= RELOGIN_EVERY_N_STEPS;

    if (needLogin) {
      if (state.stepsSinceLogin >= RELOGIN_EVERY_N_STEPS) {
        lowSlowReauths.add(1, { trafficLabel: 'low_slow_bot' });
      }

      const loginSucceeded = doLogin(profile, state, headers);

      if (!loginSucceeded) {
        cadenceSleep(profile);
        return;
      }

      // Login sonrası hemen yeni adıma geçmeden kısa sabit bekleme
      cadenceSleep(profile);
    }

    const authParams = buildAuthParams(headers, state.token);

    const useSearch = Math.random() < SEARCH_RATIO;
    const result = useSearch ? doSearch(authParams) : doProfile(authParams);

    // 401/403 geldiyse token bozulmuş kabul edip sonraki iterasyonda tekrar login
    if (result.res.status === 401 || result.res.status === 403) {
      state.token = null;
      state.stepsSinceLogin = 0;
    } else {
      state.stepsSinceLogin += 1;
    }

    cadenceSleep(profile);
  });
}