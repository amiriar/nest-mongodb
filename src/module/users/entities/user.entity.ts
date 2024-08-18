import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type UserDocument = User & Document;

@Schema({ timestamps: true })
export class User {
  // @Prop({ type: String, required: false, unique: true })
  // id: string;

  @Prop({ required: false })
  username: string;

  @Prop({ required: false })
  email: string;

  @Prop({ required: false })
  password: string;
  
  @Prop({ required: true })
  phoneNumber: string;

  @Prop({ required: false })
  profile: string;

  @Prop({ default: "USER" })
  role: string;
  
  @Prop({ required: false })
  lastDateIn: string;

  @Prop({ required: false })
  otp: string;

  @Prop({ required: false })
  otpExpiresAt: Date;

  @Prop({ required: false })
  refreshToken: string;
  
  @Prop({ required: false })
  refreshTokenExpiresAt: Date;
  
  @Prop({ default: Date.now })
  createdAt: Date;

  @Prop({ default: Date.now })
  updatedAt: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);
