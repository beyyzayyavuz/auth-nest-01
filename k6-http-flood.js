import http from 'k6/http';
import { check } from 'k6';
import { SharedArray } from 'k6/data';
import { Trend, Rate, Counter } from 'k6/metrics';
import exec from 'k6/execution';

const BASE_URL = 'http://localhost:3000';

const floodDuration = new Trend('flood_request_duration', true);
const floodFailures = new Rate('flood_logical_failures');
const floodRequests = new Counter('flood_requests');

const userAgents = new SharedArray('userAgents', function () {
  return [
    'FloodBot/1.0',
    'FloodBot/1.1',
    'AggressiveClient/2.0',
  ];
});

const floodTerms = new SharedArray('floodTerms', function () {
  return [
    'güvenlik',
    'veri',
    'analiz',
    'tez',
    'fingerprint',
    'saldırı',
    'koruma',
    'yapay-zeka',
  ];
});

export const options = {
  scenarios: {
    http_flood: {
      executor: 'constant-arrival-rate',
      exec: 'httpFloodFlow',
      rate: 12,
      timeUnit: '1s',
      duration: '90s',
      preAllocatedVUs: 20,
      maxVUs: 60,
      tags: { trafficLabel: 'http_flood' },
    },
  },
  thresholds: {
    'flood_request_duration{trafficLabel:http_flood}': ['p(95)<2500'],
  },
};

function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function buildHeaders() {
  const fakeIp = `10.10.1.${(exec.vu.idInTest % 254) + 1}`;

  return {
    'x-simulation-label': 'http_flood',
    'User-Agent': randomItem(userAgents),
    'x-test-client-ip': fakeIp,
  };
}

export function httpFloodFlow() {
  const headers = buildHeaders();
  const term = randomItem(floodTerms);
  const page = Math.floor(Math.random() * 5) + 1;
  const limit = 10;

  const res = http.get(
    `${BASE_URL}/user/search?q=${encodeURIComponent(term)}&page=${page}&limit=${limit}`,
    { headers },
  );

  floodDuration.add(res.timings.duration, { trafficLabel: 'http_flood' });
  floodRequests.add(1, { trafficLabel: 'http_flood' });

  const ok = check(res, {
    'flood response valid': (r) => [200, 401, 403, 429, 500].includes(r.status),
  });

  if (!ok) {
    floodFailures.add(1, { trafficLabel: 'http_flood' });
  }
}