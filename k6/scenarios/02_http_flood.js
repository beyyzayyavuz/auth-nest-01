import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';
import exec from 'k6/execution';
import { pickWeightedUA, NAIVE_ATTACKER_AGENTS, randomItem } from '../common/ua-pool.js';
import { getIpPool } from '../common/ip-pool.js';
import { TEST_USERS } from '../common/legitimate-user-flow.js';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const SCENARIO_ID = __ENV.SCENARIO_ID || 'S2_http_flood';

const floodLoginRequests = new Counter('flood_login_requests');
const floodSearchRequests = new Counter('flood_search_requests');
const floodLoginSuccess = new Rate('flood_login_success');

const heavyTerms = ['güvenlik', 'veri', 'analiz', 'koruma', 'tez', 'fingerprint', 'saldırı'];

export const options = {
  scenarios: {
    http_flood: {
      executor: 'ramping-arrival-rate',
      exec: 'flow',
      startRate: 20,
      timeUnit: '1s',
      preAllocatedVUs: 50,
      maxVUs: 200,
      stages: [
        { target: 50,  duration: '2m'  },
        { target: 150, duration: '15m' },
        { target: 200, duration: '10m' },  // peak
        { target: 0,   duration: '3m'  },
      ],
      tags: { trafficLabel: 'http_flood', scenarioId: SCENARIO_ID },
    },
  },
};

const profiles = {};
function profile(role = 'naive') {
  const vu = exec.vu.idInTest || 1;
  if (profiles[vu]) return profiles[vu];
  const pool = getIpPool(role);
  profiles[vu] = {
    ip: pool[(vu - 1) % pool.length],
    ua: pickWeightedUA(NAIVE_ATTACKER_AGENTS),
    user: TEST_USERS[(vu - 1) % TEST_USERS.length],
  };
  return profiles[vu];
}

export function flow() {
  const p = profile('naive');
  const baseHeaders = {
    'Content-Type':       'application/json',
    'x-simulation-label': 'http_flood',
    'x-scenario-id': SCENARIO_ID,
    'x-test-client-ip':   p.ip,
    'User-Agent':         p.ua,
  };

  // Login (her iteration'da yeniden)
  floodLoginRequests.add(1, { trafficLabel: 'http_flood' });
  const loginRes = http.post(`${BASE_URL}/auth/login`, JSON.stringify(p.user),
    { headers: baseHeaders });
  const loginOk = [200, 201].includes(loginRes.status);
  floodLoginSuccess.add(loginOk ? 1 : 0, { trafficLabel: 'http_flood' });
  if (!loginOk) return;

  let token;
  try { token = loginRes.json('accessToken'); } catch { return; }
  if (!token) return;

  const authHeaders = { ...baseHeaders, Authorization: `Bearer ${token}` };

  // Burst — 2-5 search hit
  const burst = Math.floor(Math.random() * 4) + 2;
  for (let i = 0; i < burst; i++) {
    floodSearchRequests.add(1, { trafficLabel: 'http_flood' });
    const term = randomItem(heavyTerms);
    http.get(
      `${BASE_URL}/user/search?q=${encodeURIComponent(term)}&page=${(i % 5) + 1}&limit=10`,
      { headers: authHeaders }
    );
    if (i < burst - 1) sleep(0.01 + Math.random() * 0.04); // 10-50ms
  }
}
export default flow;