// k6/scenarios/07_mix_slow.js
// Legitimate users + low-rate scraping bot paralel.

import http from 'k6/http';
import { sleep } from 'k6';
import exec from 'k6/execution';
import { runLegitSession, TEST_USERS } from '../common/legitimate-user-flow.js';
import { pickWeightedUA, NAIVE_ATTACKER_AGENTS, randomItem } from '../common/ua-pool.js';
import { getIpPool } from '../common/ip-pool.js';
import { botCadence } from '../common/cadence.js';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const SCENARIO_ID = __ENV.SCENARIO_ID || 'S3_low_rate_bot';
const RELOGIN_EVERY = 30;
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
      tags: { trafficLabel: 'normal_user_mix_slow', scenarioId: SCENARIO_ID },
    },
    slow_bot: {
      executor: 'constant-vus',
      exec: 'slowBotFlow',
      vus: 5,
      duration: '30m',
      tags: { trafficLabel: 'low_rate_bot_mix', scenarioId: SCENARIO_ID },
    },
  },
};

export function normalFlow() {
  runLegitSession(BASE_URL, 'legit', 'normal_user_mix_slow');
}

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
    'x-simulation-label': 'low_rate_bot_mix',
    'x-scenario-id': SCENARIO_ID,
    'x-test-client-ip':   s.ip,
    'User-Agent':         s.ua,
  };

  if (!s.token || s.stepsSinceLogin >= RELOGIN_EVERY) {
    const r = http.post(`${BASE_URL}/auth/login`, JSON.stringify(s.user), { headers });
    if ([200, 201].includes(r.status)) {
      try { s.token = r.json('accessToken'); } catch { s.token = null; }
      s.stepsSinceLogin = 0;
    } else {
      s.token = null;
    }
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