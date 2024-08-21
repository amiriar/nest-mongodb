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
import { Request, Response } from 'express';
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
import { JwtService } from '@nestjs/jwt';
import { UserDocument } from '../users/entities/user.entity';
import * as dotenv from 'dotenv';
import { TokenInterceptor } from 'src/interceptors/refreshToken.interceptor';

dotenv.config();
dayjs.extend(jalaliday);

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly jwtService: JwtService,
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

    const { accessToken } = await this.authService.signTokens(user);

    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 Days
    });

    // Send a success response
    res.status(200).send({ message: 'Login successful' });
  }

  @Post('refresh-token')
  @HttpCode(200)
  @ApiOperation({ summary: 'Refresh access token' })
  @ApiBody({
    schema: {
      properties: {
        refreshToken: { type: 'string', example: 'your-refresh-token-here' },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'Token refreshed successfully.' })
  @ApiResponse({ status: 401, description: 'Invalid refresh token.' })
  async refreshToken(
    @Body('refreshToken') refreshToken: string,
    @Res() res: Response,
  ) {
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token is required.');
    }

    let payload;
    try {
      payload = this.jwtService.verify(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET_KEY,
      });
    } catch (e) {
      throw new UnauthorizedException('Invalid refresh token.');
    }

    const user = (await this.userService.findOne(payload.id)) as UserDocument;
    if (!user || user.refreshToken !== refreshToken) {
      throw new UnauthorizedException(
        'User not found or invalid refresh token.',
      );
    }

    const { accessToken, refreshToken: newRefreshToken } =
      await this.authService.signTokens(user);

    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 Days
    });

    res
      .status(200)
      .send({ message: 'Token refreshed successfully', accessToken });
  }

  @Post('logout')
  @HttpCode(200)
  @ApiOperation({ summary: 'Logout the user' })
  @ApiBearerAuth()
  @ApiResponse({ status: 200, description: 'Logout successful.' })
  async logout(@Res() res: Response, @Req() req: Request) {
    const user = req.user as UserDocument;
    if (user) {
      await this.authService.clearRefreshToken(user.id);
    }

    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    res.send({ message: 'Logout successful' });
  }

  @Post('change-pass')
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
  @UseInterceptors(TokenInterceptor)
  @ApiBearerAuth()
  @HttpCode(200)
  @ApiOperation({ summary: 'Get the user info' })
  @ApiResponse({ status: 200, description: 'User info.' })
  async whoami(@Req() req: Request) {
    // req.user is populated by the guard
    const user = req?.user;
    
    return user;
  }
}
