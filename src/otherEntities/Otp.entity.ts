import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';
import { User } from 'src/module/users/entities/user.entity';

export type OtpDocument = Otp & Document;

@Schema({ timestamps: { createdAt: 'createdAt' } })
export class Otp {
  @Prop({ required: true })
  otp: string;

  @Prop({ type: Types.ObjectId, ref: User.name, required: true })
  user: Types.ObjectId;

  @Prop({ required: true })
  expiresAt: Date;
}

export const OtpSchema = SchemaFactory.createForClass(Otp);
