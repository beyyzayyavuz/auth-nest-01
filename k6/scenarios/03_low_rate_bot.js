import http from 'k6/http';
import { sleep, group } from 'k6';
import exec from 'k6/execution';
import { pickWeightedUA, NAIVE_ATTACKER_AGENTS, randomItem } from '../common/ua-pool.js';
import { getIpPool } from '../common/ip-pool.js';
import { botCadence } from '../common/cadence.js';
import { TEST_USERS } from '../common/legitimate-user-flow.js';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const SCENARIO_ID = __ENV.SCENARIO_ID || 'S3_low_rate_bot';

const RELOGIN_EVERY = 30;
const steadyTerms = ['veri', 'analiz', 'güvenlik'];

export const options = {
  scenarios: {
    low_rate_bot: {
      executor: 'constant-vus',
      exec: 'flow',
      vus: 5,
      duration: '30m',
      tags: { trafficLabel: 'low_rate_bot', scenarioId: SCENARIO_ID },
    },
  },
};

const states = {};
function state() {
  const vu = exec.vu.idInTest || 1;
  if (states[vu]) return states[vu];
  const pool = getIpPool('naive');
  states[vu] = {
    vu,
    ip: pool[(vu - 1) % pool.length],
    ua: pickWeightedUA(NAIVE_ATTACKER_AGENTS),
    user: TEST_USERS[(vu - 1) % TEST_USERS.length],
    token: null,
    stepsSinceLogin: 0,
  };
  return states[vu];
}

export function flow() {
  const s = state();
  const headers = {
    'Content-Type':       'application/json',
    'x-simulation-label': 'low_rate_bot',
    'x-test-client-ip':   s.ip,
    'User-Agent':         s.ua,
  };

  // Re-login periyodik
  if (!s.token || s.stepsSinceLogin >= RELOGIN_EVERY) {
    const r = http.post(`${BASE_URL}/auth/login`, JSON.stringify(s.user),
      { headers });
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

  // Bot cadence — log-normal mean ~2.2s, σ=0.3 (insan'a yakın görünüm)
  sleep(botCadence(2.2, 0.3));
}
export default flow;