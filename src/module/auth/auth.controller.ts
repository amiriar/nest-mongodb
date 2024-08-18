import {
  Controller,
  Post,
  Body,
  Res,
  HttpCode,
  UseGuards,
  BadRequestException,
  Req,
  Get,
  UnauthorizedException,
  UseInterceptors,
} from '@nestjs/common';
import { Response } from 'express';
import { AuthService } from './auth.service';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBody,
  ApiBearerAuth,
} from '@nestjs/swagger';
import * as dayjs from 'dayjs';
import * as jalaliday from 'jalaliday';
import { UsersService } from '../users/users.service';
import { RefreshTokenInterceptor } from 'src/interceptors/Auth.interceptor';

dayjs.extend(jalaliday);

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly userService: UsersService,
  ) {}

  @Post('send-otp')
  @HttpCode(201)
  @ApiOperation({ summary: "Send OTP to user's phone" })
  @ApiBody({
    schema: {
      properties: {
        phone: {
          type: 'string',
          example: '09102711050',
        },
      },
    },
  })
  @ApiResponse({ status: 201, description: 'OTP sent successfully.' })
  @ApiResponse({ status: 400, description: 'Phone number is required.' })
  async sendOTP(@Body('phone') phone: string) {
    if (!phone) {
      throw new BadRequestException('شماره تلفن مورد نیاز است.');
    }
    const madeIn = dayjs().calendar('jalali').format('YYYY/MM/DD HH:mm');
    let user = await this.userService.findOneByPhone(phone);

    if (!user) {
      user = await this.userService.createUser(phone, madeIn);
    }

    const otp = this.userService.generateOtp();
    // @ts-ignore
    await this.userService.saveOtp(user._id, otp);

    await this.userService.sendOtpToPhone(phone, otp);

    return {
      message: 'OTP با موفقیت ارسال شد.',
      otp,
    };
  }

  @Post('login')
  @HttpCode(200)
  @ApiOperation({ summary: 'User login with phone and OTP' })
  @ApiBody({
    schema: {
      properties: {
        phone: { type: 'string', example: '09102711050' },
        code: { type: 'string', example: '12345' },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'Login successful.' })
  @ApiResponse({ status: 401, description: 'Invalid OTP or phone number.' })
  async login(
    @Body('phone') phone: string,
    @Body('code') code: string,
    @Res() res: Response,
  ) {
    const lastDateIn = dayjs().calendar('jalali').format('YYYY/MM/DD HH:mm');
    const user = await this.authService.validateUser(phone, code, lastDateIn);
    const { accessToken, refreshToken } =
      await this.authService.signToken(user);

    // @ts-ignore
    await this.authService.saveRefreshToken(user._id, refreshToken);

    // Set the access token as a cookie
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      maxAge: 86400000, // 24 hours
    });

    res.status(200).send({ message: 'Login successful' });
  }

  @Post('logout')
  // @UseInterceptors(RefreshTokenInterceptor)
  @HttpCode(200)
  @ApiOperation({ summary: 'Logout the user' })
  @ApiBearerAuth()
  @ApiResponse({ status: 200, description: 'Logout successful.' })
  async logout(@Res() res: Response) {
    res.clearCookie('accessToken');
    res.send({ message: 'Logout successful' });
  }

  @Post('change-pass')
  @UseInterceptors(RefreshTokenInterceptor)
  @HttpCode(200)
  @ApiOperation({ summary: 'Change user password' })
  @ApiBearerAuth()
  @ApiBody({
    schema: {
      properties: {
        oldPassword: { type: 'string', example: 'oldPass123' },
        newPassword: { type: 'string', example: 'newPass456' },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'Password changed successfully.' })
  @ApiResponse({ status: 401, description: 'Unauthorized.' })
  async changePassword(
    @Body('oldPassword') oldPassword: string,
    @Body('newPassword') newPassword: string,
  ) {
    return this.authService.changePassword(oldPassword, newPassword);
  }

  @Get('whoami')
  @UseInterceptors(RefreshTokenInterceptor)
  @HttpCode(200)
  @ApiOperation({ summary: 'get the user info' })
  @ApiBearerAuth()
  @ApiResponse({ status: 200, description: 'users info.' })
  async whoami(@Req() req: Request) {
    // @ts-ignore
    const userId = req.user.id;
    return this.userService.findOne(userId);
  }
}
