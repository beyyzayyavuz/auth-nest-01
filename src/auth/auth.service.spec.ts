import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { JwtService } from '@nestjs/jwt'; // Eğer Jwt kullanıyorsan
import { UserService } from '../user/user.service'; // UserService bağımlılığı
import { PrismaService } from '../prisma/prisma.service'; // Prisma bağımlılığı
import { jest, describe, it, expect, beforeEach } from '@jest/globals';

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        // Bağımlı olunan tüm servisleri mock'luyoruz
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn(),
            verify: jest.fn(),
          },
        },
        {
          provide: UserService,
          useValue: {
            findByEmail: jest.fn(),
            create: jest.fn(),
          },
        },
        {
          provide: PrismaService,
          useValue: {
            // Prisma metodlarını buraya ekleyebilirsin
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});