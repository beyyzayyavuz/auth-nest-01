// MIMICRY FLOOD — mimicry holdout test scenario.
// UA: legit havuzu (sophisticated)
// IP: legit'le overlap'lı havuz
// Token-reuse pattern (sticky)
// Burst rate flood seviyesinde
//
// Bu scenario test-only kalmalı (Week 3 Day 17 mimicry holdout).

import http from 'k6/http';
import { sleep } from 'k6';
import exec from 'k6/execution';
import {
  pickWeightedUA, SOPHISTICATED_ATTACKER_AGENTS, randomItem,
  ACCEPT_LANGS, ACCEPT_ENCS,
} from '../common/ua-pool.js';
import { getIpPool } from '../common/ip-pool.js';
import { TEST_USERS } from '../common/legitimate-user-flow.js';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const SCENARIO_ID = __ENV.SCENARIO_ID || 'S5_mimicry_flood';

const heavyTerms = ['güvenlik', 'veri', 'analiz', 'koruma', 'tez', 'fingerprint', 'saldırı'];

export const options = {
  scenarios: {
    mimicry_flood: {
      executor: 'ramping-arrival-rate',
      exec: 'flow',
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
      tags: { trafficLabel: 'mimicry_flood', scenarioId: SCENARIO_ID },
    },
  },
};

const states = {};
function state() {
  const vu = exec.vu.idInTest || 1;
  if (states[vu]) return states[vu];
  const pool = getIpPool('sophisticated');
  states[vu] = {
    ip:   pool[(vu - 1) % pool.length],
    ua:   pickWeightedUA(SOPHISTICATED_ATTACKER_AGENTS),
    lang: randomItem(ACCEPT_LANGS),
    enc:  randomItem(ACCEPT_ENCS),
    user: TEST_USERS[(vu - 1) % TEST_USERS.length],
    token: null,
    iterationCount: 0,
  };
  return states[vu];
}

export function flow() {
  const s = state();
  const headers = {
    'Content-Type':       'application/json',
    'Accept':             'application/json, text/plain, */*',
    'Accept-Language':    s.lang,
    'Accept-Encoding':    s.enc,
    'x-simulation-label': 'mimicry_flood',
    'x-scenario-id': SCENARIO_ID,
    'x-test-client-ip':   s.ip,
    'User-Agent':         s.ua,
  };

  // Token-reuse — flood pattern'in tersine, sadece 50 iteration'da bir login
  if (!s.token || s.iterationCount >= 50) {
    const r = http.post(`${BASE_URL}/auth/login`, JSON.stringify(s.user), { headers });
    if ([200, 201].includes(r.status)) {
      try { s.token = r.json('accessToken'); } catch { s.token = null; }
      s.iterationCount = 0;
    } else { s.token = null; return; }
  }

  const authHeaders = { ...headers, Authorization: `Bearer ${s.token}` };

  // Burst — yine 2-5 search ama sticky token'la
  const burst = Math.floor(Math.random() * 4) + 2;
  for (let i = 0; i < burst; i++) {
    const term = randomItem(heavyTerms);
    http.get(
      `${BASE_URL}/user/search?q=${encodeURIComponent(term)}&page=${(i % 5) + 1}&limit=10`,
      { headers: authHeaders }
    );
    if (i < burst - 1) sleep(0.01 + Math.random() * 0.04);
  }
  s.iterationCount += 1;
}
export default flow;