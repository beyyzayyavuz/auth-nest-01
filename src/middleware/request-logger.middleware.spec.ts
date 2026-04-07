import { describe, it, expect } from '@jest/globals';
import { RequestLoggerMiddleware } from './request-logger.middleware';

describe('RequestLoggerMiddleware', () => {
  it('should be defined', () => {
    // Fake LogsService
    const fakeLogsService = {
      saveLog: () => {}, // sadece boş bir fonksiyon
    };

    const middleware = new RequestLoggerMiddleware(fakeLogsService as any);
    expect(middleware).toBeDefined();
  });
});//improve
