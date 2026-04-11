import { Test, TestingModule } from '@nestjs/testing';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { jest, describe, it, expect, beforeEach } from '@jest/globals';

describe('UserController', () => {
  let controller: UserController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [UserController],
      // UserService'i mock (sahte) olarak sağlıyoruz
      providers: [
  {
    provide: UserService,
    useValue: {
      // Fonksiyonu en basit haliyle tanımlıyoruz
      simulateSearch: jest.fn(async () => {
        return []; // Boş bir array döndüren asenkron fonksiyon
      }),
    },
  },
],
    }).compile();

    controller = module.get<UserController>(UserController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});