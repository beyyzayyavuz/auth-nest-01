// k6/scenarios/06_mix_flood.js
// Legitimate users + HTTP flood paralel.
// Mix scenario: detection model'inin attack ile legit'i ayırt etmesi gereken
// realistic test ortamı.

import http from 'k6/http';
import { sleep } from 'k6';
import exec from 'k6/execution';
import { runLegitSession, TEST_USERS } from '../common/legitimate-user-flow.js';
import { pickWeightedUA, NAIVE_ATTACKER_AGENTS, randomItem } from '../common/ua-pool.js';
import { getIpPool } from '../common/ip-pool.js';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const SCENARIO_ID = __ENV.SCENARIO_ID || 'S2_http_flood';

const heavyTerms = ['güvenlik', 'veri', 'analiz', 'koruma', 'tez', 'fingerprint', 'saldırı'];

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
      tags: { trafficLabel: 'normal_user_mix_flood', scenarioId: SCENARIO_ID },
    },
    flood: {
      executor: 'ramping-arrival-rate',
      exec: 'floodFlow',
      startRate: 20,
      timeUnit: '1s',
      preAllocatedVUs: 50,
      maxVUs: 200,
      stages: [
        { target: 50,  duration: '2m'  },
        { target: 150, duration: '15m' },
        { target: 200, duration: '10m' },
        { target: 0,   duration: '3m'  },
      ],
      tags: { trafficLabel: 'http_flood_mix', scenarioId: SCENARIO_ID },
    },
  },
};

// ===== Normal user side (legit common module) =====
export function normalFlow() {
  runLegitSession(BASE_URL, 'legit', 'normal_user_mix_flood');
}

// ===== Flood side (inline, duplicated from 02_http_flood.js) =====
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
    'x-simulation-label': 'http_flood_mix',
    'x-scenario-id': SCENARIO_ID,
    'x-test-client-ip':   p.ip,
    'User-Agent':         p.ua,
  };

  const loginRes = http.post(`${BASE_URL}/auth/login`, JSON.stringify(p.user),
    { headers });
  if (![200, 201].includes(loginRes.status)) return;

  let token;
  try { token = loginRes.json('accessToken'); } catch { return; }
  if (!token) return;

  const authHeaders = { ...headers, Authorization: `Bearer ${token}` };
  const burst = Math.floor(Math.random() * 4) + 2;  // 2-5
  for (let i = 0; i < burst; i++) {
    const term = randomItem(heavyTerms);
    http.get(
      `${BASE_URL}/user/search?q=${encodeURIComponent(term)}&page=${(i % 5) + 1}&limit=10`,
      { headers: authHeaders }
    );
    if (i < burst - 1) sleep(0.01 + Math.random() * 0.04);
  }
}

export default normalFlow;  // CLI override fallback