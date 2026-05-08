import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { SharedArray } from 'k6/data';
import { Trend, Rate, Counter } from 'k6/metrics';
import exec from 'k6/execution';

const BASE_URL = 'http://localhost:3000';

// ----------------------------------------------------
// MIX MODE
// light = kontrollü birleşik trafik
// heavy = daha görünür birleşik baskı
// ----------------------------------------------------
const MIX_MODE = (__ENV.MIX_MODE || 'light').toLowerCase();

if (!['light', 'heavy'].includes(MIX_MODE)) {
  throw new Error(`Invalid MIX_MODE: ${MIX_MODE}. Use light or heavy.`);
}

const LABELS = {
  normal: `normal_user_mix_all_${MIX_MODE}`,
  flood: `http_flood_mix_all_${MIX_MODE}`,
  slow: `low_slow_mix_all_${MIX_MODE}`,
};

// ----------------------------------------------------
// CONFIG
// ----------------------------------------------------
function getScenarioConfig() {
  if (MIX_MODE === 'heavy') {
    return {
      // Normal kullanıcıyı biraz koruyoruz ki tüm etki flood'a dönüşmesin
      normalStages: [
        { duration: '30s', target: 4 },
        { duration: '90s', target: 7 },
        { duration: '30s', target: 0 },
      ],

      // Flood: mix_http_heavy kadar sert değil, ama belirgin
      floodStages: [
        { target: 2, duration: '30s' },
        { target: 4, duration: '60s' },
        { target: 6, duration: '60s' },
        { target: 0, duration: '20s' },
      ],
      floodPreAllocatedVUs: 20,
      floodMaxVUs: 40,

      // Low-slow: görünür ama floodlaşmasın
      slowVUs: 3,
      slowDuration: '2m30s',
      reloginEverySteps: 24,
      slowCadenceBase: 2.00,
      slowCadenceStep: 0.05,
      minJitter: 0.02,
      maxJitter: 0.08,
      searchRatio: 0.80,
    };
  }

  // light
  return {
    normalStages: [
      { duration: '30s', target: 4 },
      { duration: '90s', target: 8 },
      { duration: '30s', target: 0 },
    ],

    floodStages: [
      { target: 1, duration: '30s' },
      { target: 2, duration: '60s' },
      { target: 3, duration: '60s' },
      { target: 0, duration: '20s' },
    ],
    floodPreAllocatedVUs: 10,
    floodMaxVUs: 20,

    slowVUs: 2,
    slowDuration: '2m30s',
    reloginEverySteps: 30,
    slowCadenceBase: 2.35,
    slowCadenceStep: 0.08,
    minJitter: 0.02,
    maxJitter: 0.09,
    searchRatio: 0.80,
  };
}

const cfg = getScenarioConfig();

// ----------------------------------------------------
// NORMAL METRICS
// ----------------------------------------------------
const normalLoginDuration = new Trend('mix_all_normal_login_duration', true);
const normalProfileDuration = new Trend('mix_all_normal_profile_duration', true);
const normalSearchDuration = new Trend('mix_all_normal_search_duration', true);
const normalLogicalFailures = new Rate('mix_all_normal_logical_failures');
const normalCompletedSessions = new Counter('mix_all_normal_completed_sessions');

// ----------------------------------------------------
// FLOOD METRICS
// ----------------------------------------------------
const floodLoginDuration = new Trend('mix_all_flood_login_duration', true);
const floodSearchDuration = new Trend('mix_all_flood_search_duration', true);
const floodLoginSuccess = new Rate('mix_all_flood_login_success');
const floodSearchSuccess = new Rate('mix_all_flood_search_success');
const floodCompletedBursts = new Counter('mix_all_flood_completed_bursts');

// ----------------------------------------------------
// LOW-SLOW METRICS
// ----------------------------------------------------
const slowLoginDuration = new Trend('mix_all_slow_login_duration', true);
const slowStepDuration = new Trend('mix_all_slow_step_duration', true);
const slowLoginSuccess = new Rate('mix_all_slow_login_success');
const slowStepSuccess = new Rate('mix_all_slow_step_success');
const slowLogins = new Counter('mix_all_slow_logins');
const slowSteps = new Counter('mix_all_slow_steps');
const slowSearches = new Counter('mix_all_slow_searches');
const slowProfiles = new Counter('mix_all_slow_profiles');
const slowReauths = new Counter('mix_all_slow_reauths');

// ----------------------------------------------------
// DATA
// ----------------------------------------------------
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

const legitAgents = new SharedArray('legitAgents', function () {
  return [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ChromeLikeUser',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) SafariLikeUser',
    'Mozilla/5.0 (X11; Linux x86_64) FirefoxLikeUser',
  ];
});

const floodAgents = new SharedArray('floodAgents', function () {
  return [
    'FloodBot/1.0',
    'FloodBot/1.1',
    'AggressiveClient/2.0',
  ];
});

const slowAgents = new SharedArray('slowAgents', function () {
  return [
    'PeriodicStealthBot/1.0',
    'LowRateClient/1.2',
    'SlowProbe/2.0',
  ];
});

const popularTerms = ['güvenlik', 'veri'];
const longTailTerms = ['analiz', 'yapay-zeka', 'saldırı', 'koruma', 'tez', 'fingerprint'];
const heavyTerms = ['güvenlik', 'veri', 'analiz', 'koruma', 'tez', 'fingerprint', 'saldırı'];
const steadyTerms = ['veri', 'analiz', 'güvenlik'];

// ----------------------------------------------------
// OPTIONS
// ----------------------------------------------------
export const options = {
  scenarios: {
    normal_user_mix_all: {
      executor: 'ramping-vus',
      exec: 'normalUserMixAllFlow',
      startVUs: 0,
      stages: cfg.normalStages,
      gracefulRampDown: '10s',
      tags: { trafficLabel: LABELS.normal },
    },

    http_flood_mix_all: {
      executor: 'ramping-arrival-rate',
      exec: 'httpFloodMixAllFlow',
      startRate: cfg.floodStages[0].target,
      timeUnit: '1s',
      preAllocatedVUs: cfg.floodPreAllocatedVUs,
      maxVUs: cfg.floodMaxVUs,
      stages: cfg.floodStages,
      tags: { trafficLabel: LABELS.flood },
    },

    low_slow_mix_all: {
      executor: 'constant-vus',
      exec: 'lowSlowMixAllFlow',
      vus: cfg.slowVUs,
      duration: cfg.slowDuration,
      tags: { trafficLabel: LABELS.slow },
    },
  },

  thresholds: {
    [`http_req_duration{trafficLabel:${LABELS.normal}}`]: ['p(95)<3000'],
    [`http_req_failed{trafficLabel:${LABELS.normal}}`]: ['rate<0.20'],
    [`mix_all_normal_logical_failures{trafficLabel:${LABELS.normal}}`]: ['rate<0.20'],

    [`mix_all_flood_login_duration{trafficLabel:${LABELS.flood}}`]: ['p(95)<7000'],
    [`mix_all_flood_search_duration{trafficLabel:${LABELS.flood}}`]: ['p(95)<5000'],

    [`mix_all_slow_login_duration{trafficLabel:${LABELS.slow}}`]: ['p(95)<6000'],
    [`mix_all_slow_step_duration{trafficLabel:${LABELS.slow}}`]: ['p(95)<4000'],
  },
};

// ----------------------------------------------------
// HELPERS
// ----------------------------------------------------
function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function think(minSeconds, maxSeconds) {
  sleep(Math.random() * (maxSeconds - minSeconds) + minSeconds);
}

function parseToken(res) {
  try {
    return res.json('accessToken');
  } catch (_) {
    return null;
  }
}

// ====================================================
// NORMAL USER FLOW
// ====================================================
function pickLegitUser() {
  return randomItem(users);
}

function pickLegitUA() {
  return randomItem(legitAgents);
}

function pickLegitSearchTerm() {
  if (Math.random() < 0.65) return randomItem(popularTerms);
  return randomItem(longTailTerms);
}

function buildLegitHeaders() {
  const fakeIp = `192.168.70.${(exec.vu.idInTest % 253) + 1}`;

  return {
    'Content-Type': 'application/json',
    'x-simulation-label': LABELS.normal,
    'x-test-client-ip': fakeIp,
    'User-Agent': pickLegitUA(),
  };
}

function chooseLegitJourney() {
  const r = Math.random();
  if (r < 0.45) return 'profile_then_search';
  if (r < 0.70) return 'search_twice_then_profile';
  if (r < 0.90) return 'profile_only';
  return 'search_only';
}

export function normalUserMixAllFlow() {
  const user = pickLegitUser();
  const headers = buildLegitHeaders();

  group('Normal User Under Combined Traffic', function () {
    const loginRes = http.post(
      `${BASE_URL}/auth/login`,
      JSON.stringify(user),
      { headers }
    );

    normalLoginDuration.add(loginRes.timings.duration, {
      trafficLabel: LABELS.normal,
    });

    const loginKnown = check(loginRes, {
      'normal mix-all login known': (r) => [200, 201, 401, 403, 429, 500].includes(r.status),
    });

    const token = parseToken(loginRes);

    if (!loginKnown || !token || ![200, 201].includes(loginRes.status)) {
      normalLogicalFailures.add(1, { trafficLabel: LABELS.normal });
      think(1.0, 2.0);
      return;
    }

    const authParams = {
      headers: {
        ...headers,
        Authorization: `Bearer ${token}`,
      },
    };

    const journey = chooseLegitJourney();

    if (journey === 'profile_then_search') {
      think(1.5, 4.0);

      const profileRes = http.get(`${BASE_URL}/user/profile`, authParams);
      normalProfileDuration.add(profileRes.timings.duration, {
        trafficLabel: LABELS.normal,
      });
      check(profileRes, {
        'normal mix-all profile known': (r) => [200, 401, 403, 429, 500].includes(r.status),
      });

      think(1.0, 3.0);

      const term = pickLegitSearchTerm();
      const page = Math.floor(Math.random() * 5) + 1;
      const searchRes = http.get(
        `${BASE_URL}/user/search?q=${encodeURIComponent(term)}&page=${page}&limit=10`,
        authParams
      );
      normalSearchDuration.add(searchRes.timings.duration, {
        trafficLabel: LABELS.normal,
      });
      check(searchRes, {
        'normal mix-all search known': (r) => [200, 401, 403, 429, 500].includes(r.status),
      });
    } else if (journey === 'search_twice_then_profile') {
      think(1.5, 3.0);

      for (let i = 0; i < 2; i++) {
        const term = pickLegitSearchTerm();
        const page = Math.floor(Math.random() * 3) + 1;

        const searchRes = http.get(
          `${BASE_URL}/user/search?q=${encodeURIComponent(term)}&page=${page}&limit=10`,
          authParams
        );

        normalSearchDuration.add(searchRes.timings.duration, {
          trafficLabel: LABELS.normal,
        });

        check(searchRes, {
          'normal mix-all search known': (r) => [200, 401, 403, 429, 500].includes(r.status),
        });

        think(0.8, 2.0);
      }

      const profileRes = http.get(`${BASE_URL}/user/profile`, authParams);
      normalProfileDuration.add(profileRes.timings.duration, {
        trafficLabel: LABELS.normal,
      });

      check(profileRes, {
        'normal mix-all profile known': (r) => [200, 401, 403, 429, 500].includes(r.status),
      });
    } else if (journey === 'profile_only') {
      think(1.0, 3.0);

      const profileRes = http.get(`${BASE_URL}/user/profile`, authParams);
      normalProfileDuration.add(profileRes.timings.duration, {
        trafficLabel: LABELS.normal,
      });

      check(profileRes, {
        'normal mix-all profile known': (r) => [200, 401, 403, 429, 500].includes(r.status),
      });
    } else {
      think(1.0, 3.0);

      const term = pickLegitSearchTerm();
      const page = Math.floor(Math.random() * 5) + 1;

      const searchRes = http.get(
        `${BASE_URL}/user/search?q=${encodeURIComponent(term)}&page=${page}&limit=10`,
        authParams
      );

      normalSearchDuration.add(searchRes.timings.duration, {
        trafficLabel: LABELS.normal,
      });

      check(searchRes, {
        'normal mix-all search known': (r) => [200, 401, 403, 429, 500].includes(r.status),
      });
    }

    normalCompletedSessions.add(1, {
      trafficLabel: LABELS.normal,
    });
  });
}

// ====================================================
// HTTP FLOOD FLOW
// ====================================================
function stableFloodProfile() {
  const vuId = exec.vu.idInTest || 1;

  return {
    ip: `10.10.70.${(vuId % 253) + 1}`,
    userAgent: floodAgents[(vuId - 1) % floodAgents.length],
    user: users[(vuId - 1) % users.length],
  };
}

function buildFloodHeaders(profile) {
  return {
    'Content-Type': 'application/json',
    'x-simulation-label': LABELS.flood,
    'x-test-client-ip': profile.ip,
    'User-Agent': profile.userAgent,
  };
}

export function httpFloodMixAllFlow() {
  const profile = stableFloodProfile();
  const headers = buildFloodHeaders(profile);

  group('HTTP Flood Under Combined Traffic', function () {
    const loginRes = http.post(
      `${BASE_URL}/auth/login`,
      JSON.stringify(profile.user),
      { headers }
    );

    floodLoginDuration.add(loginRes.timings.duration, {
      trafficLabel: LABELS.flood,
    });

    const loginSuccess = [200, 201].includes(loginRes.status);
    floodLoginSuccess.add(loginSuccess ? 1 : 0, {
      trafficLabel: LABELS.flood,
    });

    check(loginRes, {
      'flood mix-all login known': (r) => [200, 201, 401, 403, 429, 500].includes(r.status),
    });

    const token = parseToken(loginRes);

    if (!token || !loginSuccess) {
      return;
    }

    const authParams = {
      headers: {
        ...headers,
        Authorization: `Bearer ${token}`,
      },
    };

    const burstSize =
      MIX_MODE === 'heavy'
        ? Math.floor(Math.random() * 3) + 2 // 2-4
        : Math.floor(Math.random() * 2) + 1; // 1-2

    for (let i = 0; i < burstSize; i++) {
      const term = randomItem(heavyTerms);
      const page = (i % 5) + 1;

      const searchRes = http.get(
        `${BASE_URL}/user/search?q=${encodeURIComponent(term)}&page=${page}&limit=10`,
        authParams
      );

      floodSearchDuration.add(searchRes.timings.duration, {
        trafficLabel: LABELS.flood,
      });

      const searchSuccess = searchRes.status === 200;
      floodSearchSuccess.add(searchSuccess ? 1 : 0, {
        trafficLabel: LABELS.flood,
      });

      check(searchRes, {
        'flood mix-all search known': (r) => [200, 401, 403, 429, 500].includes(r.status),
      });

      if (i < burstSize - 1) {
        sleep(
          MIX_MODE === 'heavy'
            ? Math.random() * 0.12 + 0.03
            : Math.random() * 0.25 + 0.10
        );
      }
    }

    floodCompletedBursts.add(1, {
      trafficLabel: LABELS.flood,
    });
  });
}

// ====================================================
// LOW-SLOW FLOW
// ====================================================
const slowVuStates = {};

function stableSlowProfile() {
  const vuId = exec.vu.idInTest || 1;

  return {
    vuId,
    ip: `10.20.70.${(vuId % 253) + 1}`,
    userAgent: slowAgents[(vuId - 1) % slowAgents.length],
    user: users[(vuId - 1) % users.length],
    cadenceBase: cfg.slowCadenceBase + (((vuId - 1) % 4) * cfg.slowCadenceStep),
  };
}

function getSlowVuState() {
  const vuId = exec.vu.idInTest || 1;

  if (!slowVuStates[vuId]) {
    slowVuStates[vuId] = {
      token: null,
      stepsSinceLogin: 0,
    };
  }

  return slowVuStates[vuId];
}

function buildSlowHeaders(profile) {
  return {
    'Content-Type': 'application/json',
    'x-simulation-label': LABELS.slow,
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

function cadenceSleep(profile) {
  const jitter = Math.random() * (cfg.maxJitter - cfg.minJitter) + cfg.minJitter;
  sleep(profile.cadenceBase + jitter);
}

function doSlowLogin(profile, state, headers) {
  slowLogins.add(1, { trafficLabel: LABELS.slow });

  const loginRes = http.post(
    `${BASE_URL}/auth/login`,
    JSON.stringify(profile.user),
    { headers }
  );

  slowLoginDuration.add(loginRes.timings.duration, {
    trafficLabel: LABELS.slow,
  });

  const loginKnown = check(loginRes, {
    'low-slow mix-all login known': (r) => [200, 201, 400, 401, 403, 429, 500].includes(r.status),
  });

  const success = loginRes.status === 200 || loginRes.status === 201;
  slowLoginSuccess.add(success ? 1 : 0, {
    trafficLabel: LABELS.slow,
  });

  if (!loginKnown || !success) {
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

function doSlowProfile(authParams) {
  slowProfiles.add(1, { trafficLabel: LABELS.slow });
  slowSteps.add(1, { trafficLabel: LABELS.slow });

  const res = http.get(`${BASE_URL}/user/profile`, authParams);

  slowStepDuration.add(res.timings.duration, {
    trafficLabel: LABELS.slow,
  });

  check(res, {
    'low-slow mix-all profile known': (r) => [200, 401, 403, 429, 500].includes(r.status),
  });

  const success = res.status === 200;
  slowStepSuccess.add(success ? 1 : 0, {
    trafficLabel: LABELS.slow,
  });

  return res;
}

function doSlowSearch(authParams) {
  slowSearches.add(1, { trafficLabel: LABELS.slow });
  slowSteps.add(1, { trafficLabel: LABELS.slow });

  const term = randomItem(steadyTerms);
  const page = Math.random() < 0.75 ? 1 : 2;
  const limit = 10;

  const res = http.get(
    `${BASE_URL}/user/search?q=${encodeURIComponent(term)}&page=${page}&limit=${limit}`,
    authParams
  );

  slowStepDuration.add(res.timings.duration, {
    trafficLabel: LABELS.slow,
  });

  check(res, {
    'low-slow mix-all search known': (r) => [200, 401, 403, 429, 500].includes(r.status),
  });

  const success = res.status === 200;
  slowStepSuccess.add(success ? 1 : 0, {
    trafficLabel: LABELS.slow,
  });

  return res;
}

export function lowSlowMixAllFlow() {
  const profile = stableSlowProfile();
  const state = getSlowVuState();
  const headers = buildSlowHeaders(profile);

  group('Low-Slow Under Combined Traffic', function () {
    const needLogin =
      !state.token || state.stepsSinceLogin >= cfg.reloginEverySteps;

    if (needLogin) {
      if (state.stepsSinceLogin >= cfg.reloginEverySteps) {
        slowReauths.add(1, { trafficLabel: LABELS.slow });
      }

      const loginSucceeded = doSlowLogin(profile, state, headers);

      if (!loginSucceeded) {
        cadenceSleep(profile);
        return;
      }

      cadenceSleep(profile);
    }

    const authParams = buildAuthParams(headers, state.token);
    const useSearch = Math.random() < cfg.searchRatio;
    const res = useSearch ? doSlowSearch(authParams) : doSlowProfile(authParams);

    if (res.status === 401 || res.status === 403) {
      state.token = null;
      state.stepsSinceLogin = 0;
    } else {
      state.stepsSinceLogin += 1;
    }

    cadenceSleep(profile);
  });
}