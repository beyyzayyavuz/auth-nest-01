// Legitimate insan davranışı — Markov + log-normal think + Zipf search.
// Tüm "normal user" senaryolarında bu modül kullanılır (mix dahil).

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';
import exec from 'k6/execution';
import {
  pickWeightedUA, LEGIT_AGENTS, ACCEPT_LANGS, ACCEPT_ENCS, randomItem,
} from './ua-pool.js';
import { getIpPool } from './ip-pool.js';
import { THINK, sessionLength, zipfSample } from './cadence.js';

const SCENARIO_ID = __ENV.SCENARIO_ID || 'manual';
// VU state cache (her VU için 1 kez)
const vuStates = {};

// Markov geçiş matrisi — test app endpoint'lerine özgü
const transitionMatrix = {
  start:   { profile: 0.30, search: 0.55, exit: 0.15 },
  profile: { search:  0.55, profile: 0.10, exit: 0.35 },
  search:  { search:  0.45, profile: 0.30, exit: 0.25 },
};

const searchTerms = [
  'güvenlik', 'veri', 'analiz', 'yapay-zeka', 'saldırı',
  'koruma', 'tez', 'fingerprint', 'performans', 'log',
  'authentication', 'token', 'middleware', 'entropy', 'ddos',
];

// Test users — register edilmiş hesaplar
export const TEST_USERS = [
  { email: 'user01@example.com', password: 'TestUser@2026!' },
  { email: 'user02@example.com', password: 'SecurePass@101' },
  { email: 'user03@example.com', password: 'DemoLogin@2026' },
  { email: 'user04@example.com', password: 'UserAccess@404' },
  { email: 'user05@example.com', password: 'ProfileTest@55' },
  { email: 'user06@example.com', password: 'SearchUser@77' },
  { email: 'user07@example.com', password: 'NormalFlow@88' },
  { email: 'user08@example.com', password: 'SessionTest@99' },
  { email: 'user09@example.com', password: 'ApiClient@123' },
  { email: 'user10@example.com', password: 'TrafficUser@10' },
];

export function getVuState(role = 'legit', label = 'normal_user') {
  const vuId = exec.vu.idInTest || 1;
  if (vuStates[vuId]) return vuStates[vuId];

  const ipPool = getIpPool(role);
  const userIdx = (vuId - 1) % TEST_USERS.length;
  const ipIdx = (vuId - 1) % ipPool.length;

  vuStates[vuId] = {
    vuId,
    label,
    user: TEST_USERS[userIdx],
    fakeIp: ipPool[ipIdx],
    userAgent: pickWeightedUA(LEGIT_AGENTS),
    acceptLanguage: randomItem(ACCEPT_LANGS),
    acceptEncoding: randomItem(ACCEPT_ENCS),
    accessToken: null,
    pagesRemaining: sessionLength(),
    lastPageState: 'start',
  };
  return vuStates[vuId];
}

export function buildBaseHeaders(state) {
  return {
    'Content-Type':       'application/json',
    'Accept':             'application/json, text/plain, */*',
    'x-scenario-id': SCENARIO_ID,
    'Accept-Language':    state.acceptLanguage,
    'Accept-Encoding':    state.acceptEncoding,
    'x-simulation-label': state.label,
    'User-Agent':         state.userAgent,
    'x-test-client-ip':   state.fakeIp,
  };
}

export function buildAuthHeaders(state, referer = null) {
  const h = {
    ...buildBaseHeaders(state),
    Authorization: `Bearer ${state.accessToken}`,
  };
  if (referer) h['Referer'] = referer;
  return h;
}

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

function pickSearchTerm() {
  return searchTerms[zipfSample(searchTerms.length, 1.0)];
}

export function ensureAuthenticated(state, baseUrl) {
  if (state.accessToken) return true;

  const res = http.post(
    `${baseUrl}/auth/login`,
    JSON.stringify(state.user),
    { headers: buildBaseHeaders(state) },
  );

  if (![200, 201].includes(res.status)) {
    state.accessToken = null;
    return false;
  }
  try { state.accessToken = res.json('accessToken'); }
  catch { return false; }
  if (!state.accessToken) return false;
  sleep(THINK.medium());
  return true;
}

export function doProfileRequest(state, baseUrl) {
  if (!ensureAuthenticated(state, baseUrl)) return false;
  const res = http.get(`${baseUrl}/user/profile`,
    { headers: buildAuthHeaders(state, `${baseUrl}/dashboard`) });
  if ([401, 403].includes(res.status)) {
    state.accessToken = null;
    if (!ensureAuthenticated(state, baseUrl)) return false;
  }
  return res.status === 200;
}

export function doSearchRequest(state, baseUrl, maxPage = 5) {
  if (!ensureAuthenticated(state, baseUrl)) return false;
  const term = pickSearchTerm();
  const page = Math.floor(Math.random() * maxPage) + 1;
  const url = `${baseUrl}/user/search?q=${encodeURIComponent(term)}&page=${page}&limit=10`;
  const res = http.get(url, { headers: buildAuthHeaders(state, `${baseUrl}/search`) });
  if ([401, 403].includes(res.status)) {
    state.accessToken = null;
    if (!ensureAuthenticated(state, baseUrl)) return false;
  }
  return res.status === 200;
}

export function doLogoutRequest(state, baseUrl) {
  if (!state.accessToken) return true;
  const res = http.post(`${baseUrl}/auth/logout`, null,
    { headers: buildAuthHeaders(state) });
  state.accessToken = null;
  state.pagesRemaining = sessionLength();
  state.lastPageState = 'start';
  return [200, 201, 204].includes(res.status);
}

// Tek session simülasyonu — tüm normal user senaryolarında çağrılır
export function runLegitSession(baseUrl, role = 'legit', label = 'normal_user') {
  const state = getVuState(role, label);

  group('User Session', function () {
    sleep(THINK.short());
    while (state.pagesRemaining > 0) {
      const next = nextState(state.lastPageState);
      if (next === 'exit') break;

      let ok = false;
      if (next === 'profile') ok = doProfileRequest(state, baseUrl);
      else if (next === 'search') ok = doSearchRequest(state, baseUrl, 5);

      if (!ok) { sleep(THINK.medium());  break; }
      state.lastPageState = next;
      state.pagesRemaining -= 1;

      if (next === 'profile') sleep(THINK.long());
      else sleep(THINK.medium());
    }

    // %8 explicit logout
    if (Math.random() < 0.08 && state.accessToken) {
      sleep(THINK.medium());
      doLogoutRequest(state, baseUrl);
    } else {
      state.accessToken = null;
      state.pagesRemaining = sessionLength();
      state.lastPageState = 'start';
    }

    // Inter-session gap — heavy-tailed
    sleep(THINK.long());
  });
}