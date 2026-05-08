// k6/scenarios/08_mix_all.js
// Legitimate + http_flood + low_rate_bot paralel.
// En karmaşık mix: detection model'inin üç class'ı simultaneous ayırt etmesi.

import http from 'k6/http';
import { sleep } from 'k6';
import exec from 'k6/execution';
import { runLegitSession, TEST_USERS } from '../common/legitimate-user-flow.js';
import { pickWeightedUA, NAIVE_ATTACKER_AGENTS, randomItem } from '../common/ua-pool.js';
import { getIpPool } from '../common/ip-pool.js';
import { botCadence } from '../common/cadence.js';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const SCENARIO_ID = __ENV.SCENARIO_ID || 'S_mix_all';
const RELOGIN_EVERY = 30;
const heavyTerms = ['güvenlik', 'veri', 'analiz', 'koruma', 'tez', 'fingerprint', 'saldırı'];
const steadyTerms = ['veri', 'analiz', 'güvenlik'];

export const options = {
  scenarios: {
    normal: {
      executor: 'ramping-vus',
      exec: 'normalFlow',
      startVUs: 0,
      stages: [
        { duration: '2m',  target: 5  },
        { duration: '25m', target: 15 },
        { duration: '3m',  target: 0  },
      ],
      gracefulRampDown: '30s',
      tags: { trafficLabel: 'normal_user_mix_all', scenarioId: SCENARIO_ID },
    },
    flood: {
      executor: 'ramping-arrival-rate',
      exec: 'floodFlow',
      startRate: 10,
      timeUnit: '1s',
      preAllocatedVUs: 30,
      maxVUs: 100,
      stages: [
        { target: 30,  duration: '2m'  },
        { target: 80,  duration: '15m' },
        { target: 100, duration: '10m' },
        { target: 0,   duration: '3m'  },
      ],
      tags: { trafficLabel: 'http_flood_mix_all', scenarioId: SCENARIO_ID },
    },
    slow_bot: {
      executor: 'constant-vus',
      exec: 'slowBotFlow',
      vus: 3,
      duration: '30m',
      tags: { trafficLabel: 'low_rate_bot_mix_all', scenarioId: SCENARIO_ID },
    },
  },
};

export function normalFlow() {
  runLegitSession(BASE_URL, 'legit', 'normal_user_mix_all');
}

// Flood (06_mix_flood'dan kopya)
const floodProfiles = {};
function floodProfile() {
  const vu = exec.vu.idInTest || 1;
  if (floodProfiles[vu]) return floodProfiles[vu];
  const pool = getIpPool('naive');
  floodProfiles[vu] = {
    ip: pool[(vu - 1) % pool.length],
    ua: pickWeightedUA(NAIVE_ATTACKER_AGENTS),
    user: TEST_USERS[(vu - 1) % TEST_USERS.length],
  };
  return floodProfiles[vu];
}

export function floodFlow() {
  const p = floodProfile();
  const headers = {
    'Content-Type':       'application/json',
    'x-simulation-label': 'http_flood_mix_all',
    'x-test-client-ip':   p.ip,
    'User-Agent':         p.ua,
  };
  const loginRes = http.post(`${BASE_URL}/auth/login`, JSON.stringify(p.user), { headers });
  if (![200, 201].includes(loginRes.status)) return;
  let token;
  try { token = loginRes.json('accessToken'); } catch { return; }
  if (!token) return;
  const authHeaders = { ...headers, Authorization: `Bearer ${token}` };
  const burst = Math.floor(Math.random() * 4) + 2;
  for (let i = 0; i < burst; i++) {
    const term = randomItem(heavyTerms);
    http.get(
      `${BASE_URL}/user/search?q=${encodeURIComponent(term)}&page=${(i % 5) + 1}&limit=10`,
      { headers: authHeaders }
    );
    if (i < burst - 1) sleep(0.01 + Math.random() * 0.04);
  }
}

// Slow bot (07_mix_slow'dan kopya)
const botStates = {};
function botState() {
  const vu = exec.vu.idInTest || 1;
  if (botStates[vu]) return botStates[vu];
  const pool = getIpPool('naive');
  botStates[vu] = {
    ip: pool[(vu - 1) % pool.length],
    ua: pickWeightedUA(NAIVE_ATTACKER_AGENTS),
    user: TEST_USERS[(vu - 1) % TEST_USERS.length],
    token: null,
    stepsSinceLogin: 0,
  };
  return botStates[vu];
}

export function slowBotFlow() {
  const s = botState();
  const headers = {
    'Content-Type':       'application/json',
    'x-simulation-label': 'low_rate_bot_mix_all',
    'x-test-client-ip':   s.ip,
    'User-Agent':         s.ua,
  };
  if (!s.token || s.stepsSinceLogin >= RELOGIN_EVERY) {
    const r = http.post(`${BASE_URL}/auth/login`, JSON.stringify(s.user), { headers });
    if ([200, 201].includes(r.status)) {
      try { s.token = r.json('accessToken'); } catch { s.token = null; }
      s.stepsSinceLogin = 0;
    } else { s.token = null; }
    sleep(botCadence(2.2));
    return;
  }
  const authHeaders = { ...headers, Authorization: `Bearer ${s.token}` };
  const useSearch = Math.random() < 0.80;
  if (useSearch) {
    const term = randomItem(steadyTerms);
    const page = Math.random() < 0.75 ? 1 : 2;
    http.get(`${BASE_URL}/user/search?q=${term}&page=${page}&limit=10`,
      { headers: authHeaders });
  } else {
    http.get(`${BASE_URL}/user/profile`, { headers: authHeaders });
  }
  s.stepsSinceLogin += 1;
  sleep(botCadence(2.2, 0.3));
}

export default normalFlow;