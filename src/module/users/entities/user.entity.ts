import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type UserDocument = User & Document;

@Schema({ timestamps: true })
export class User {
  @Prop({ required: false })
  firstname: string;

  @Prop({ required: false })
  lastname: string;

  @Prop({ required: false, unique: true })
  username: string;

  @Prop({ required: false, unique: true })
  email: string;

  @Prop({ required: false })
  password: string;
  
  @Prop({ required: true })
  phoneNumber: string;

  @Prop({ default: null })
  profile: string;

  @Prop({ required: false })
  lastDateIn: string;
  
  @Prop({ default: Date.now })
  createdAt: Date;

  @Prop({ default: Date.now })
  updatedAt: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);
