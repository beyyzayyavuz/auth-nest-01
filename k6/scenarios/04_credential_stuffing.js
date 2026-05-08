import http from 'k6/http';
import { sleep } from 'k6';
import { Counter, Rate } from 'k6/metrics';
import exec from 'k6/execution';
import { pickWeightedUA, NAIVE_ATTACKER_AGENTS } from '../common/ua-pool.js';
import { getIpPool } from '../common/ip-pool.js';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const SCENARIO_ID = __ENV.SCENARIO_ID || 'S4_credential_stuffing';

const stuffingAttempts = new Counter('stuffing_attempts');
const stuffing401Rate = new Rate('stuffing_401_rate');

export const options = {
  scenarios: {
    credential_stuffing: {
      executor: 'ramping-arrival-rate',
      exec: 'flow',
      startRate: 10,
      timeUnit: '1s',
      preAllocatedVUs: 30,
      maxVUs: 100,
      stages: [
        { target: 30, duration: '2m'  },
        { target: 80, duration: '15m' },
        { target: 100, duration: '10m' },
        { target: 0,  duration: '3m'  },
      ],
      tags: { trafficLabel: 'credential_stuffing', scenarioId: SCENARIO_ID },
    },
  },
};

const states = {};
function state() {
  const vu = exec.vu.idInTest || 1;
  if (states[vu]) return states[vu];
  const pool = getIpPool('naive');
  states[vu] = {
    ip: pool[(vu - 1) % pool.length],
    ua: pickWeightedUA(NAIVE_ATTACKER_AGENTS),
  };
  return states[vu];
}

function randomEmail() {
  return `attacker${Math.random().toString(36).slice(2, 10)}@example.com`;
}

function randomPassword() {
  return Math.random().toString(36).slice(2, 12);
}

export function flow() {
  const s = state();
  stuffingAttempts.add(1);
  const res = http.post(
    `${BASE_URL}/auth/login`,
    JSON.stringify({ email: randomEmail(), password: randomPassword() }),
    {
      headers: {
        'Content-Type':       'application/json',
        'x-simulation-label': 'credential_stuffing',
        'x-scenario-id': SCENARIO_ID,
        'x-test-client-ip':   s.ip,
        'User-Agent':         s.ua,
      },
    }
  );
  stuffing401Rate.add(res.status === 401 ? 1 : 0);
}
export default flow;