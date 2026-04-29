import { AsyncLocalStorage } from 'async_hooks';

export interface RequestMetrics {
  dbQueryCount: number;
  dbTotalTimeMs: number;
  externalCallCount: number;
  tRecv: number;          // ms epoch
  tHandlerStart: number;  // performance.now() ms
  tHandlerEnd: number;
  cpuStart: NodeJS.CpuUsage;
}

export const requestContext = new AsyncLocalStorage<RequestMetrics>();