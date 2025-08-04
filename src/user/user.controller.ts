// src/user/user.controller.ts
import {
  Body,
  Controller,
  Delete,
  Get,
  Patch,
  Put,
  Request,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { UserService } from './user.service';

@Controller('user')
@UseGuards(JwtAuthGuard) // Bu şekilde tüm endpointleri korur
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get('profile')
  getProfile(@Request() req) {
    return {
      message: 'Profile fetched successfully',
      user: req.user,
    };
  }

  @Put('update')
  async updateProfile(@Request() req, @Body() body) {
    return this.userService.updateUser(req.user.userId, body);
  }

  @Patch('change-password')
  async changePassword(@Request() req, @Body() body) {
    return this.userService.changePassword(
      req.user.userId,
      body.oldPassword,
      body.newPassword,
    );
  }

  @Delete('delete')
  async deleteAccount(@Request() req) {
    return this.userService.deleteUser(req.user.userId);
  }
}
