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
import { User, UserDocument } from '../users/entities/user.entity';
import { Role, RoleDocument } from 'src/otherEntities/role.entity';
import { UsersService } from '../users/users.service';
import * as dotenv from 'dotenv';
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
      throw new UnauthorizedException('User not found.');
    }

    if (new Date() > user.otpExpiresAt) {
      throw new UnauthorizedException('OTP has expired.');
    }

    if (user.otp === code) {
      user.lastDateIn = lastDateIn;
      user.otp = null;
      user.otpExpiresAt = null;
      return user.save();
    } else {
      throw new UnauthorizedException('Invalid OTP.');
    }
  }

  async signTokens(user: UserDocument) {
    const payload = { id: user._id, role: user.role };

    const accessToken = this.jwtService.sign(payload, {
      secret: process.env.JWT_SECRET_KEY,
      expiresIn: '1m', // Access token expiration
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: process.env.JWT_REFRESH_SECRET_KEY,
      expiresIn: '7d', // Refresh token expiration
    });

    // Save the refresh token in the database
    user.refreshToken = refreshToken;
    await user.save();

    return { accessToken, refreshToken };
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

  async clearRefreshToken(userId: string) {
    await this.userModel.findByIdAndUpdate(userId, { refreshToken: null });
  }

  async refreshTokens(refreshToken: string): Promise<{ accessToken: string }> {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET_KEY,
      });
      const user = await this.userModel.findById(payload.id);
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      const newAccessToken = this.jwtService.sign(
        { id: user._id, role: user.role },
        { secret: process.env.JWT_SECRET_KEY, expiresIn: '1m' }, // 30 minutes expiry
      );

      return { accessToken: newAccessToken };
    } catch (err) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }
}
