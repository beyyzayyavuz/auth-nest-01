// DEMO SCENARIO — Defense için 45 saniyelik mini koşum.
// Legit user flow kullanır. Ramping-VUs, 10 VU peak.
// Tam iterasyon (login + search + logout) tamamlanabilsin diye 45 saniye.
// scenarioId = "DEMO".
//
// Çalıştırma:
//   SCENARIO_ID="DEMO" k6 run k6/scenarios/demo_short.js
//
// Beklenen: ~45 saniyede 50-100 request, en az 1-2 tam iterasyon,
// DB'ye düşer, Nginx log akar, endpoint cost capture edilir.

import { runLegitSession } from '../common/legitimate-user-flow.js';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const SCENARIO_ID = __ENV.SCENARIO_ID || 'DEMO';

export const options = {
  scenarios: {
    demo: {
      executor: 'ramping-vus',
      exec: 'flow',
      startVUs: 0,
      stages: [
        { duration: '5s',  target: 5  },   // ramp-up
        { duration: '35s', target: 10 },   // peak demo (35s — tam iterasyon için yeterli)
        { duration: '5s',  target: 0  },   // ramp-down
      ],
      gracefulRampDown: '5s',
      tags: { trafficLabel: 'demo', scenarioId: SCENARIO_ID },
    },
  },
};

export function flow() {
  runLegitSession(BASE_URL, 'legit', 'normal_user');
}

export default flow;
