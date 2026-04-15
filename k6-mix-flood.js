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

// ------------------ NORMAL SIDE ----------------------
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
  const fakeIp = `192.168.20.${(exec.vu.idInTest % 253) + 1}`;

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

export function normalUserMixHttpFlow() {
  const user = pickLegitUser();
  const headers = buildLegitHeaders();

  group('Normal User Under HTTP Flood', function () {
    const loginRes = http.post(
      `${BASE_URL}/auth/login`,
      JSON.stringify(user),
      { headers }
    );

    normalLoginDuration.add(loginRes.timings.duration, {
      trafficLabel: LABELS.normal,
    });

    const loginOk = check(loginRes, {
      'normal mix login response known': (r) => [200, 201, 401, 403, 429, 500].includes(r.status),
    });

    const token = parseToken(loginRes);

    if (!loginOk || !token || ![200, 201].includes(loginRes.status)) {
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
        'normal mix profile known': (r) => [200, 401, 403, 429, 500].includes(r.status),
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
        'normal mix search known': (r) => [200, 401, 403, 429, 500].includes(r.status),
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
          'normal mix search known': (r) => [200, 401, 403, 429, 500].includes(r.status),
        });
        think(0.8, 2.0);
      }

      const profileRes = http.get(`${BASE_URL}/user/profile`, authParams);
      normalProfileDuration.add(profileRes.timings.duration, {
        trafficLabel: LABELS.normal,
      });
      check(profileRes, {
        'normal mix profile known': (r) => [200, 401, 403, 429, 500].includes(r.status),
      });
    } else if (journey === 'profile_only') {
      think(1.0, 3.0);
      const profileRes = http.get(`${BASE_URL}/user/profile`, authParams);
      normalProfileDuration.add(profileRes.timings.duration, {
        trafficLabel: LABELS.normal,
      });
      check(profileRes, {
        'normal mix profile known': (r) => [200, 401, 403, 429, 500].includes(r.status),
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
        'normal mix search known': (r) => [200, 401, 403, 429, 500].includes(r.status),
      });
    }

    normalCompletedSessions.add(1, {
      trafficLabel: LABELS.normal,
    });
  });
}

// ------------------ FLOOD SIDE -----------------------
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