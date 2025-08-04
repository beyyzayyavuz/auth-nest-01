import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaClient, User } from '@prisma/client';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UserService {
  private prisma = new PrismaClient();

  async createUser(email: string, password: string): Promise<User> {
    const hashedPassword = await bcrypt.hash(password, 10);

    return this.prisma.user.create({
      data: {
        email,
        password: hashedPassword,
      },
    });
  }

  async findUserByEmail(email: string): Promise<User | null> {
    return this.prisma.user.findUnique({
      where: { email },
    });
  }

  async findUserById(userId: number) {
    return this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        password: true,
        createdAt: true,
        refreshToken: true,
      },
    });
  }
  // user.service.ts
  async updateUser(userId: number, updateData: Partial<User>) {
    return this.prisma.user.update({
      where: { id: userId },
      data: updateData,
    });
  }
  async changePassword(userId: number, oldPass: string, newPass: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const valid = await bcrypt.compare(oldPass, user.password);
    if (!valid) throw new UnauthorizedException('Old password incorrect');

    const hashed = await bcrypt.hash(newPass, 10);
    return this.prisma.user.update({
      where: { id: userId },
      data: { password: hashed },
    });
  }
  async deleteUser(userId: number) {
    return this.prisma.user.delete({ where: { id: userId } });
  }
}
