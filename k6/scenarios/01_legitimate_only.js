import { runLegitSession } from '../common/legitimate-user-flow.js';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const SCENARIO_ID = __ENV.SCENARIO_ID || 'S1_legit_only';

export const options = {
  scenarios: {
    legit_users: {
      executor: 'ramping-vus',
      exec: 'flow',
      startVUs: 0,
      stages: [
        { duration: '2m',  target: 30  },   // ← 5 → 30
        { duration: '25m', target: 100 },   // ← 15 → 100
        { duration: '3m',  target: 0   },
      ],
      gracefulRampDown: '30s',
      tags: { trafficLabel: 'normal_user', scenarioId: SCENARIO_ID },
    },
  },
};

export function flow() {
  runLegitSession(BASE_URL, 'legit', 'normal_user');
}

export default flow;
