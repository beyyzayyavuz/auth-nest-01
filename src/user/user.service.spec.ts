import { Test, TestingModule } from '@nestjs/testing';
import { UserService } from './user.service';
import { jest, describe, it, expect, beforeEach } from '@jest/globals';
import { PrismaService } from '../prisma/prisma.service'; // Prisma bağımlılığını ekle

describe('UserService', () => {
  let service: UserService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserService,
        {
          provide: PrismaService,
          useValue: {
            user: {
              findMany: jest.fn(), // Arama fonksiyonu için sahte metot
              findUnique: jest.fn(),
            },
          },
        },
      ],
    }).compile();

    service = module.get<UserService>(UserService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});