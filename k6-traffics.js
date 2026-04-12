import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { SharedArray } from 'k6/data';
import { Trend, Rate, Counter } from 'k6/metrics';
import exec from 'k6/execution';

const BASE_URL = 'http://localhost:3000';

// Custom metrics
const loginDuration = new Trend('app_login_duration', true);
const profileDuration = new Trend('app_profile_duration', true);
const searchDuration = new Trend('app_search_duration', true);
const logoutDuration = new Trend('app_logout_duration', true);

const logicalFailures = new Rate('app_logical_failures');
const startedSessions = new Counter('app_started_sessions');
const completedSessions = new Counter('app_completed_sessions');
const abortedSessions = new Counter('app_aborted_sessions');

// Seeded users
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

const userAgents = new SharedArray('userAgents', function () {
  return [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ChromeLikeUser',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) SafariLikeUser',
    'Mozilla/5.0 (X11; Linux x86_64) FirefoxLikeUser',
  ];
});

// Search behavior
const popularTerms = ['güvenlik', 'veri'];
const longTailTerms = ['analiz', 'yapay-zeka', 'saldırı', 'koruma', 'tez', 'fingerprint'];

export const options = {
  scenarios: {
    legit_users: {
      executor: 'ramping-vus',
      exec: 'legitimateUserFlow',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 5 },
        { duration: '2m', target: 15 },
        { duration: '30s', target: 0 },
      ],
      gracefulRampDown: '10s',
      tags: { trafficLabel: 'normal_user' },
    },
  },
  thresholds: {
    'http_req_duration{trafficLabel:normal_user}': ['p(95)<1000'],
    'http_req_failed{trafficLabel:normal_user}': ['rate<0.10'],
    'app_logical_failures{trafficLabel:normal_user}': ['rate<0.08'],
    'app_login_duration{trafficLabel:normal_user}': ['p(95)<1000'],
    'app_search_duration{trafficLabel:normal_user}': ['p(95)<1200'],
  },
};

function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function pickUser() {
  return randomItem(users);
}

function pickUA() {
  return randomItem(userAgents);
}

function pickSearchTerm() {
  if (Math.random() < 0.65) {
    return randomItem(popularTerms);
  }
  return randomItem(longTailTerms);
}

function randomGarbage() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789?!@#$%';
  const len = Math.floor(Math.random() * 5) + 1;

  let result = '';
  for (let i = 0; i < len; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

function maybeBadSearchTerm() {
  let term = pickSearchTerm();
  const r = Math.random();

  if (r < 0.03) {
    term = '   ';
  } else if (r < 0.06) {
    term = 'a';
  } else if (r < 0.09) {
    term = '???';
  } else if (r < 0.12) {
    term = randomGarbage();
  }

  return term;
}

function isGarbage(term) {
  const t = term.trim();

  if (t === '') return true;
  if (t.length === 1) return true;

  // Türkçe karakterler, rakam, boşluk ve tire kabul
  return !/^[a-zA-Z0-9ğüşöçıİĞÜŞÖÇ\s-]+$/.test(t);
}

function think(minSeconds, maxSeconds) {
  sleep(Math.random() * (maxSeconds - minSeconds) + minSeconds);
}

function chooseJourney() {
  const r = Math.random();

  if (r < 0.45) return 'profile_then_search';
  if (r < 0.70) return 'search_twice_then_profile';
  if (r < 0.90) return 'profile_only';
  return 'search_only';
}

function buildBaseHeaders() {
  const fakeIp = `192.168.1.${Math.floor(Math.random() * 254) + 1}`;

  return {
    'Content-Type': 'application/json',
    'x-simulation-label': 'normal_user',
    'User-Agent': pickUA(),
    //'X-Forwarded-For': fakeIp,
    'x-test-client-ip': fakeIp,
  };
}

function buildAuthParams(headers, token, sessionBroken) {
  if (sessionBroken) {
    return { headers };
  }

  return {
    headers: {
      ...headers,
      Authorization: `Bearer ${token}`,
    },
  };
}

function validProtectedStatus(response, sessionBroken) {
  return sessionBroken
    ? [200, 401, 403].includes(response.status)
    : response.status === 200;
}

function doProfileRequest(authParams, sessionBroken) {
  const profileRes = http.get(`${BASE_URL}/user/profile`, authParams);

  profileDuration.add(profileRes.timings.duration, { trafficLabel: 'normal_user' });

  const ok = check(profileRes, {
    'profile response valid': (r) => validProtectedStatus(r, sessionBroken),
  });

  if (!ok) {
    logicalFailures.add(1, { trafficLabel: 'normal_user' });
  }

  return profileRes;
}

function doSearchRequest(authParams, sessionBroken, maxPage = 5) {
  const page = Math.floor(Math.random() * maxPage) + 1;
  const limit = 10;
  const term = maybeBadSearchTerm();
  const badInput = isGarbage(term);

  const searchRes = http.get(
    `${BASE_URL}/user/search?q=${encodeURIComponent(term)}&page=${page}&limit=${limit}`,
    authParams
  );

  searchDuration.add(searchRes.timings.duration, { trafficLabel: 'normal_user' });

  const ok = check(searchRes, {
    'search response valid': (r) => {
      if (sessionBroken) {
        return [200, 400, 401, 403, 422].includes(r.status);
      }

      if (badInput) {
        return [200, 400, 422].includes(r.status);
      }

      return r.status === 200;
    },
  });

  if (!ok) {
    logicalFailures.add(1, { trafficLabel: 'normal_user' });
  }

  return searchRes;
}

function doLogoutRequest(authParams, sessionBroken) {
  const logoutRes = http.post(`${BASE_URL}/auth/logout`, null, authParams);

  logoutDuration.add(logoutRes.timings.duration, { trafficLabel: 'normal_user' });

  const ok = check(logoutRes, {
    'logout response valid': (r) =>
      sessionBroken
        ? [200, 201, 204, 401, 403].includes(r.status)
        : [200, 201, 204].includes(r.status),
  });

  if (!ok) {
    logicalFailures.add(1, { trafficLabel: 'normal_user' });
  }

  return logoutRes;
}

export function legitimateUserFlow() {
  const user = pickUser();
  const headers = buildBaseHeaders();

  // Az miktarda kusur
  const sessionBroken = Math.random() < 0.02;
  const wrongPasswordAttempt = Math.random() < 0.02;

  startedSessions.add(1, { trafficLabel: 'normal_user' });

  group('User Session', function () {
    const loginPayload = { ...user };

    if (wrongPasswordAttempt) {
      loginPayload.password = 'wrongpassword';
    }

    const loginRes = http.post(
      `${BASE_URL}/auth/login`,
      JSON.stringify(loginPayload),
      { headers }
    );

    loginDuration.add(loginRes.timings.duration, { trafficLabel: 'normal_user' });

    const loginOk = check(loginRes, {
      'login response valid': (r) =>
        wrongPasswordAttempt
          ? [400, 401, 403].includes(r.status)
          : [200, 201].includes(r.status),
    });

    if (!loginOk) {
      logicalFailures.add(1, { trafficLabel: 'normal_user' });
      abortedSessions.add(1, { trafficLabel: 'normal_user' });
      think(1.0, 2.5);
      return;
    }

    // Bilinçli yanlış şifre denemesinde session burada bitsin
    if (wrongPasswordAttempt) {
      think(1.0, 2.0);
      completedSessions.add(1, { trafficLabel: 'normal_user' });
      return;
    }

    let token = null;
    try {
      token = loginRes.json('accessToken');
    } catch (_) {
      token = null;
    }

    if (!token) {
      logicalFailures.add(1, { trafficLabel: 'normal_user' });
      abortedSessions.add(1, { trafficLabel: 'normal_user' });
      think(1.0, 2.0);
      return;
    }

    const authParams = buildAuthParams(headers, token, sessionBroken);
    const journey = chooseJourney();

    if (journey === 'profile_then_search') {
      think(1.5, 4.0);
      doProfileRequest(authParams, sessionBroken);

      think(1.0, 3.0);
      doSearchRequest(authParams, sessionBroken, 5);
    } else if (journey === 'search_twice_then_profile') {
      think(1.5, 3.5);
      doSearchRequest(authParams, sessionBroken, 3);

      think(0.8, 2.0);
      doSearchRequest(authParams, sessionBroken, 3);

      think(0.8, 2.0);
      doProfileRequest(authParams, sessionBroken);
    } else if (journey === 'profile_only') {
      think(1.0, 3.0);
      doProfileRequest(authParams, sessionBroken);
    } else {
      think(1.0, 3.0);
      doSearchRequest(authParams, sessionBroken, 5);
    }

    // Logout her zaman olmaz
    if (Math.random() < 0.35) {
      think(2.0, 5.0);
      doLogoutRequest(authParams, sessionBroken);
    }

    completedSessions.add(1, { trafficLabel: 'normal_user' });
  });
}