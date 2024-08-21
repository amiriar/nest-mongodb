import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from './entities/user.entity';
import { Otp, OtpDocument } from 'src/otherEntities/Otp.entity';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    @InjectModel(Otp.name) private otpModel: Model<OtpDocument>,
  ) {}

  async findAll(): Promise<User[]> {
    return this.userModel.find().exec();
  }

  async findOne(id: string): Promise<User> {
    return this.userModel
      .findById(id, { __v: 0, createdAt: 0, updatedAt: 0 })
      .exec();
  }

  async findOneByPhone(phone: string): Promise<User> {
    return this.userModel.findOne({ phoneNumber: phone }).exec();
  }

  async findOneByEmail(email: string): Promise<User> {
    return this.userModel.findOne({ email }).exec();
  }

  async createUser(phone: string, madeIn: string): Promise<User> {
    return this.userModel.create({ phoneNumber: phone, madeIn });
  }

  async saveUser(user: UserDocument): Promise<User> {
    const userData = await this.userModel
      .findByIdAndUpdate(user._id, user, { new: true })
      .exec();
    return userData;
  }

  async deleteUser(id: string): Promise<void> {
    const result = await this.userModel.findByIdAndDelete(id).exec();
    if (!result) {
      throw new NotFoundException('User not found');
    }
  }

  // OTP

  generateOtp(): string {
    return Math.floor(10000 + Math.random() * 90000).toString();
  }

  async saveOtp(userId: string, otp: string): Promise<Otp> {
    const user = await this.userModel.findById(userId);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const expirationTime = new Date();
    expirationTime.setMinutes(expirationTime.getMinutes() + 2); // Set OTP expiration to 2 minutes

    const newOtp = new this.otpModel({
      otp,
      user: user._id,
      expiresAt: expirationTime,
    });

    user.otp = otp;
    user.otpExpiresAt = expirationTime;

    await user.save();

    return newOtp.save();
  }

  async sendOtpToPhone(phone: string, otp: string): Promise<void> {
    // Send OTP to the phone number using an SMS service
    // Implement SMS service integration here
  }
}
