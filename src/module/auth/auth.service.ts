import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { Request, request } from 'express';
import { User, UserDocument } from '../users/entities/user.entity';
import { Role, RoleDocument } from 'src/otherEntities/role.entity';
import { UsersService } from '../users/users.service';
import * as dotenv from 'dotenv';
import { from, map, Observable } from 'rxjs';
dotenv.config();

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private readonly usersService: UsersService,
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
    @InjectModel(Role.name) private readonly roleModel: Model<RoleDocument>,
  ) {}

  async validateUser(
    phone: string,
    code: string,
    lastDateIn: string,
  ): Promise<UserDocument> {
    const user = await this.userModel.findOne({ phoneNumber: phone });

    if (!user) {
      throw new UnauthorizedException('کاربری با این شماره تلفن یافت نشد.');
    }

    if (new Date() > user.otpExpiresAt) {
      throw new UnauthorizedException('کد وارد شده منقضی شده است.');
    }

    if (user.otp === code) {
      user.lastDateIn = lastDateIn;
      user.otp = null;
      user.otpExpiresAt = null; 
      return user.save();
    } else {
      throw new UnauthorizedException('اطلاعات وارد شده صحیح نمی‌باشد.');
    }
  }

  async signToken(user: UserDocument) {
    const payload = {
      username: user.username || null,
      id: user._id,
      role: user.role,
    };
  
    const accessToken = this.jwtService.sign(payload, {
      secret: process.env.JWT_SECRET_KEY,
      expiresIn: '1m', // Access token valid for 30 minutes
    });
  
    const refreshToken = this.jwtService.sign(payload, {
      secret: process.env.JWT_REFRESH_SECRET_KEY,
      expiresIn: '7d', // Refresh token valid for 7 days
    });
  
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    user.refreshToken = hashedRefreshToken;
    user.refreshTokenExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // Expires in 7 days
    await user.save();

    return { accessToken, refreshToken: hashedRefreshToken };
  }
  

  async generateTokens(user: UserDocument) {
    const payload = {
      username: user.username,
      id: user._id,
      role: user.role,
    };

    const accessToken = this.jwtService.sign(payload, {
      secret: process.env.JWT_SECRET_KEY,
      expiresIn: '15m', // Access token expires in 15 minutes
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: process.env.JWT_REFRESH_SECRET_KEY,
      expiresIn: '7d', // Refresh token expires in 7 days
    });

    user.refreshToken = refreshToken;
    user.refreshTokenExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await user.save();

    return { accessToken, refreshToken };
  }

  refreshToken(userId: string, refreshToken: string): Observable<string> {
    return from(this.userModel.findById(userId)).pipe(
      map((user) => {
        if (!user || user.refreshToken !== refreshToken) {
          throw new UnauthorizedException('Invalid refresh token');
        }

        if (new Date() > user.refreshTokenExpiresAt) {
          throw new UnauthorizedException('Refresh token has expired');
        }

        const payload = {
          username: user.username || null,
          id: user._id,
          role: user.role,
        };

        return this.jwtService.sign(payload, {
          secret: process.env.JWT_SECRET_KEY,
          expiresIn: '1m',
        });
      }),
    );
  }

  async revokeRefreshToken(userId: string): Promise<void> {
    const user = await this.userModel.findById(userId);
    if (user) {
      user.refreshToken = null;
      user.refreshTokenExpiresAt = null;
      await user.save();
    }
  }

  async saveRefreshToken(userId: string, refreshToken: string) {
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    await this.userModel.findByIdAndUpdate(userId, { refreshToken: hashedRefreshToken });
  }

  async getRefreshToken(userId: string) {
    const user = await this.userModel.findById(userId);
    return user?.refreshToken;
  }

  async validateRefreshToken(userId: string, refreshToken: string) {
    const userRefreshToken = await this.getRefreshToken(userId);
    
    if (!userRefreshToken) {
      throw new UnauthorizedException('Invalid refresh token.');
    }
    
    const isValid = await bcrypt.compare(refreshToken, userRefreshToken);
    if (!isValid) {
      throw new UnauthorizedException('Invalid refresh token.');
    }
    return true;
  }

  async changePassword(
    oldPassword: string,
    newPassword: string,
  ): Promise<UserDocument> {
    // @ts-ignore
    const user = request.user as UserDocument;
    const userId = user._id; // Use _id for Mongoose
    if (!user) {
      throw new NotFoundException('کاربری با این مشخصات پیدا نشد.');
    }

    // Logic to change the password
    const compare = bcrypt.compareSync(newPassword, oldPassword);
    if (compare) {
      const salt = bcrypt.genSaltSync(10);
      const hash = bcrypt.hashSync(newPassword, salt);
      user.password = hash;
      await user.save();
    }

    return user; // You might return some success message or the user info
  }
}
