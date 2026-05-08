import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { SharedArray } from 'k6/data';
import { Trend, Rate, Counter } from 'k6/metrics';
import exec from 'k6/execution';

const BASE_URL = 'http://localhost:3000';

// ----------------------------------------------------
// MIX MODE
// light = kontrollü baskı
// heavy = daha belirgin baskı
// ----------------------------------------------------
const MIX_MODE = (__ENV.MIX_MODE || 'light').toLowerCase();

if (!['light', 'heavy'].includes(MIX_MODE)) {
  throw new Error(`Invalid MIX_MODE: ${MIX_MODE}. Use light or heavy.`);
}

const LABELS = {
  normal: `normal_user_mix_http_${MIX_MODE}`,
  flood: `http_flood_mix_http_${MIX_MODE}`,
};

// ----------------------------------------------------
// NORMAL USER METRICS
// ----------------------------------------------------
const normalLoginDuration = new Trend('mix_http_normal_login_duration', true);
const normalProfileDuration = new Trend('mix_http_normal_profile_duration', true);
const normalSearchDuration = new Trend('mix_http_normal_search_duration', true);
const normalLogoutDuration = new Trend('mix_http_normal_logout_duration', true);

const normalLogicalFailures = new Rate('mix_http_normal_logical_failures');
const normalCompletedSessions = new Counter('mix_http_normal_completed_sessions');

// ----------------------------------------------------
// FLOOD METRICS
// ----------------------------------------------------
const floodLoginDuration = new Trend('mix_http_flood_login_duration', true);
const floodSearchDuration = new Trend('mix_http_flood_search_duration', true);
const floodLoginSuccess = new Rate('mix_http_flood_login_success');
const floodSearchSuccess = new Rate('mix_http_flood_search_success');
const floodCompletedBursts = new Counter('mix_http_flood_completed_bursts');

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
    { email: 'user9@gmail.com', password: '8888' },
    { email: 'user10@gmail.com', password: '9999' },
    { email: 'user11@gmail.com', password: '101010' },
    { email: 'user12@gmail.com', password: '121212' },
    { email: 'user13@gmail.com', password: '131313' },
    { email: 'user14@gmail.com', password: '141414' },
    { email: 'user15@gmail.com', password: '151515' },
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

const popularTerms = ['güvenlik', 'veri'];
const longTailTerms = ['analiz', 'yapay-zeka', 'saldırı', 'koruma', 'tez', 'fingerprint'];
const heavyTerms = ['güvenlik', 'veri', 'analiz', 'koruma', 'tez', 'fingerprint', 'saldırı'];

// ----------------------------------------------------
// SCENARIO CONFIG
// ----------------------------------------------------
function getScenarioConfig() {
  if (MIX_MODE === 'heavy') {
    return {
      normalStages: [
        { duration: '30s', target: 4 },
        { duration: '90s', target: 8 },
        { duration: '30s', target: 0 },
      ],
      floodStages: [
        { target: 2, duration: '30s' },
        { target: 5, duration: '60s' },
        { target: 8, duration: '60s' },
        { target: 0, duration: '20s' },
      ],
      floodPreAllocatedVUs: 25,
      floodMaxVUs: 60,
    };
  }

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
  };
}

const cfg = getScenarioConfig();

// ----------------------------------------------------
// OPTIONS
// ----------------------------------------------------
export const options = {
  scenarios: {
    normal_user_mix_http: {
      executor: 'ramping-vus',
      exec: 'normalUserMixHttpFlow',
      startVUs: 0,
      stages: cfg.normalStages,
      gracefulRampDown: '10s',
      tags: { trafficLabel: LABELS.normal },
    },

    http_flood_mix_http: {
      executor: 'ramping-arrival-rate',
      exec: 'httpFloodMixHttpFlow',
      startRate: cfg.floodStages[0].target,
      timeUnit: '1s',
      preAllocatedVUs: cfg.floodPreAllocatedVUs,
      maxVUs: cfg.floodMaxVUs,
      stages: cfg.floodStages,
      tags: { trafficLabel: LABELS.flood },
    },
  },

  thresholds: {
    [`http_req_duration{trafficLabel:${LABELS.normal}}`]: ['p(95)<2500'],
    [`http_req_failed{trafficLabel:${LABELS.normal}}`]: ['rate<0.20'],
    [`mix_http_normal_logical_failures{trafficLabel:${LABELS.normal}}`]: ['rate<0.20'],

    [`mix_http_flood_login_duration{trafficLabel:${LABELS.flood}}`]: ['p(95)<7000'],
    [`mix_http_flood_search_duration{trafficLabel:${LABELS.flood}}`]: ['p(95)<5000'],
  },
};

// ----------------------------------------------------
// HELPERS
// ----------------------------------------------------
function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomInt(min, maxInclusive) {
  return Math.floor(Math.random() * (maxInclusive - min + 1)) + min;
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
// NORMAL SIDE (FIXED)
// ====================================================
let normalVuState = null;

function getNormalVuState() {
  if (normalVuState !== null) {
    return normalVuState;
  }

  const vuNumber = exec.vu.idInTest || 1;
  const userIndex = (vuNumber - 1) % users.length;
  const uaIndex = (vuNumber - 1) % legitAgents.length;

  normalVuState = {
    vuNumber,
    user: users[userIndex],
    userAgent: legitAgents[uaIndex],
    fakeIp: `192.168.20.${((vuNumber - 1) % 253) + 1}`,
    accessToken: null,
    actionsSinceLogin: 0,
    targetActionsThisSession: randomInt(2, 5),
  };

  return normalVuState;
}

function buildLegitHeaders(state) {
  return {
    'Content-Type': 'application/json',
    'x-simulation-label': LABELS.normal,
    'x-test-client-ip': state.fakeIp,
    'User-Agent': state.userAgent,
  };
}

function buildNormalAuthParams(state) {
  return {
    headers: {
      ...buildLegitHeaders(state),
      Authorization: `Bearer ${state.accessToken}`,
    },
  };
}

function pickLegitSearchTerm() {
  if (Math.random() < 0.65) return randomItem(popularTerms);
  return randomItem(longTailTerms);
}

function chooseLegitJourney() {
  const r = Math.random();
  if (r < 0.35) return 'profile_then_search';
  if (r < 0.60) return 'search_twice_then_profile';
  if (r < 0.80) return 'profile_only';
  return 'search_only';
}

function clearNormalSession(state) {
  state.accessToken = null;
  state.actionsSinceLogin = 0;
  state.targetActionsThisSession = randomInt(2, 5);
}

function ensureNormalAuthenticated(state) {
  if (state.accessToken) {
    return true;
  }

  const loginRes = http.post(
    `${BASE_URL}/auth/login`,
    JSON.stringify(state.user),
    { headers: buildLegitHeaders(state) }
  );

  normalLoginDuration.add(loginRes.timings.duration, {
    trafficLabel: LABELS.normal,
  });

  const loginKnown = check(loginRes, {
    'normal mix login known': (r) => [200, 201, 401, 403, 429, 500].includes(r.status),
  });

  const loginSuccess = [200, 201].includes(loginRes.status);

  if (!loginKnown || !loginSuccess) {
    normalLogicalFailures.add(1, { trafficLabel: LABELS.normal });
    clearNormalSession(state);
    return false;
  }

  const token = parseToken(loginRes);

  if (!token) {
    normalLogicalFailures.add(1, { trafficLabel: LABELS.normal });
    clearNormalSession(state);
    return false;
  }

  state.accessToken = token;
  state.actionsSinceLogin = 0;
  state.targetActionsThisSession = randomInt(2, 5);

  // login sonrası ilk aksiyona hemen geçmesin
  think(1.5, 4.0);

  return true;
}

function doNormalProfileRequest(state) {
  if (!ensureNormalAuthenticated(state)) {
    return false;
  }

  let profileRes = http.get(`${BASE_URL}/user/profile`, buildNormalAuthParams(state));
  normalProfileDuration.add(profileRes.timings.duration, {
    trafficLabel: LABELS.normal,
  });

  if ([401, 403].includes(profileRes.status)) {
    clearNormalSession(state);

    if (!ensureNormalAuthenticated(state)) {
      return false;
    }

    profileRes = http.get(`${BASE_URL}/user/profile`, buildNormalAuthParams(state));
    normalProfileDuration.add(profileRes.timings.duration, {
      trafficLabel: LABELS.normal,
    });
  }

  const known = check(profileRes, {
    'normal mix profile known': (r) => [200, 401, 403, 429, 500].includes(r.status),
  });

  const success = profileRes.status === 200;

  if (!known || !success) {
    normalLogicalFailures.add(1, { trafficLabel: LABELS.normal });
  }

  return success;
}

function doNormalSearchRequest(state, maxPage = 5) {
  if (!ensureNormalAuthenticated(state)) {
    return false;
  }

  const term = pickLegitSearchTerm();
  const page = Math.floor(Math.random() * maxPage) + 1;

  const url = `${BASE_URL}/user/search?q=${encodeURIComponent(term)}&page=${page}&limit=10`;

  let searchRes = http.get(url, buildNormalAuthParams(state));
  normalSearchDuration.add(searchRes.timings.duration, {
    trafficLabel: LABELS.normal,
  });

  if ([401, 403].includes(searchRes.status)) {
    clearNormalSession(state);

    if (!ensureNormalAuthenticated(state)) {
      return false;
    }

    searchRes = http.get(url, buildNormalAuthParams(state));
    normalSearchDuration.add(searchRes.timings.duration, {
      trafficLabel: LABELS.normal,
    });
  }

  const known = check(searchRes, {
    'normal mix search known': (r) => [200, 401, 403, 429, 500].includes(r.status),
  });

  const success = searchRes.status === 200;

  if (!known || !success) {
    normalLogicalFailures.add(1, { trafficLabel: LABELS.normal });
  }

  return success;
}

function doNormalLogoutRequest(state) {
  if (!state.accessToken) {
    return true;
  }

  const logoutRes = http.post(
    `${BASE_URL}/auth/logout`,
    null,
    buildNormalAuthParams(state)
  );

  normalLogoutDuration.add(logoutRes.timings.duration, {
    trafficLabel: LABELS.normal,
  });

  const ok = check(logoutRes, {
    'normal mix logout known': (r) => [200, 201, 204, 401, 403, 429, 500].includes(r.status),
  });

  if (!ok) {
    normalLogicalFailures.add(1, { trafficLabel: LABELS.normal });
    return false;
  }

  return true;
}

export function normalUserMixHttpFlow() {
  const state = getNormalVuState();

  group('Normal User Under HTTP Flood', function () {
    const journey = chooseLegitJourney();

    if (journey === 'profile_then_search') {
      think(1.5, 4.0);

      if (!doNormalProfileRequest(state)) {
        think(1.0, 2.5);
        return;
      }
      state.actionsSinceLogin += 1;

      think(1.0, 3.0);

      if (!doNormalSearchRequest(state, 5)) {
        think(1.0, 2.5);
        return;
      }
      state.actionsSinceLogin += 1;
    } else if (journey === 'search_twice_then_profile') {
      think(1.5, 3.0);

      if (!doNormalSearchRequest(state, 3)) {
        think(1.0, 2.5);
        return;
      }
      state.actionsSinceLogin += 1;

      think(0.8, 2.0);

      if (!doNormalSearchRequest(state, 3)) {
        think(1.0, 2.5);
        return;
      }
      state.actionsSinceLogin += 1;

      think(0.8, 2.0);

      if (!doNormalProfileRequest(state)) {
        think(1.0, 2.5);
        return;
      }
      state.actionsSinceLogin += 1;
    } else if (journey === 'profile_only') {
      think(1.0, 3.0);

      if (!doNormalProfileRequest(state)) {
        think(1.0, 2.5);
        return;
      }
      state.actionsSinceLogin += 1;
    } else {
      think(1.0, 3.0);

      if (!doNormalSearchRequest(state, 5)) {
        think(1.0, 2.5);
        return;
      }
      state.actionsSinceLogin += 1;
    }

    const shouldEndSession =
      state.actionsSinceLogin >= state.targetActionsThisSession ||
      Math.random() < 0.25;

    if (shouldEndSession) {
      if (Math.random() < 0.55) {
        think(2.0, 5.0);
        doNormalLogoutRequest(state);
      }

      clearNormalSession(state);

      normalCompletedSessions.add(1, {
        trafficLabel: LABELS.normal,
      });

      // yeni session'a hemen başlamasın
      think(15.0, 60.0);
    } else {
      // token kalsın, sonraki iteration'da reuse olsun
      think(5.0, 20.0);
    }
  });
}

// ====================================================
// FLOOD SIDE (UNCHANGED LOGIC)
// ====================================================
function stableFloodProfile() {
  const vuId = exec.vu.idInTest || 1;

  return {
    ip: `10.10.30.${(vuId % 253) + 1}`,
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

export function httpFloodMixHttpFlow() {
  const profile = stableFloodProfile();
  const headers = buildFloodHeaders(profile);

  group('HTTP Flood Against Normal Traffic', function () {
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
      'flood mix login known': (r) => [200, 201, 401, 403, 429, 500].includes(r.status),
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
        'flood mix search known': (r) => [200, 401, 403, 429, 500].includes(r.status),
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