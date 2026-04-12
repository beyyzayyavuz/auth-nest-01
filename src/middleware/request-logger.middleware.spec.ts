import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { RequestLoggerMiddleware } from './request-logger.middleware';
import { Request, Response } from 'express';
import { LogsService } from '../logs/logs.service';
import * as crypto from 'crypto';

describe('RequestLoggerMiddleware', () => {
  let middleware: RequestLoggerMiddleware;
  // HATA ÇÖZÜMÜ: Tipi en geniş haliyle tanımlıyoruz
  let mockLogsService: { saveLog: jest.Mock };
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let nextFunction: jest.Mock;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };

    // HATA ÇÖZÜMÜ: jest.fn() içine tip vermiyoruz, çıktıya 'as any' ekliyoruz
    mockLogsService = {
      saveLog: jest.fn().mockResolvedValue({} as never),
    };

    middleware = new RequestLoggerMiddleware(
      mockLogsService as unknown as LogsService,
    );

    mockRequest = {
      method: 'GET',
      url: '/user/profile',
      originalUrl: '/user/profile',
      baseUrl: '/user',
      route: { path: '/profile' } as any,
      headers: {},
      socket: { remoteAddress: '127.0.0.1' } as any,
      ip: '127.0.0.1',
    };

    // HATA ÇÖZÜMÜ: 'event' ve 'callback' için açıkça 'any' kullanıyoruz
    mockResponse = {
      statusCode: 200,
      on: jest.fn().mockImplementation((event: any, callback: any): any => {
        if (event === 'finish') {
          callback();
        }
        return mockResponse;
      }),
    } as unknown as Response;

    nextFunction = jest.fn();

    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    process.env = originalEnv;
    jest.restoreAllMocks();
  });

  it('should be defined', () => {
    expect(middleware).toBeDefined();
  });

  it('should prioritize x-test-client-ip when ALLOW_TEST_IP_HEADER=true', () => {
    process.env.ALLOW_TEST_IP_HEADER = 'true';
    const fakeIp = '192.168.1.50';
    mockRequest.headers = { 'x-test-client-ip': fakeIp };

    middleware.use(mockRequest as Request, mockResponse as Response, nextFunction as any);

    expect(mockLogsService.saveLog).toHaveBeenCalledWith(
      expect.objectContaining({ ip: fakeIp })
    );
  });

  it('should ignore x-test-client-ip when ALLOW_TEST_IP_HEADER=false', () => {
    process.env.ALLOW_TEST_IP_HEADER = 'false';
    mockRequest.headers = {
      'x-test-client-ip': '192.168.1.50',
      'x-forwarded-for': '203.0.113.195'
    };

    middleware.use(mockRequest as Request, mockResponse as Response, nextFunction as any);

    expect(mockLogsService.saveLog).toHaveBeenCalledWith(
      expect.objectContaining({ ip: '203.0.113.195' })
    );
  });

  it('should generate correct clientHash with pipe separator', () => {
    process.env.ALLOW_TEST_IP_HEADER = 'true';
    const fakeIp = '1.1.1.1';
    const ua = 'TestAgent';
    mockRequest.headers = { 
      'x-test-client-ip': fakeIp, 
      'user-agent': ua 
    };

    middleware.use(mockRequest as Request, mockResponse as Response, nextFunction as any);

    const expectedHash = crypto.createHash('md5').update(`1.1.1.1|TestAgent`).digest('hex');

    expect(mockLogsService.saveLog).toHaveBeenCalledWith(
      expect.objectContaining({ clientHash: expectedHash })
    );
  });
});