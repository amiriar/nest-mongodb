import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type TodoDocument = Todo & Document;

export enum TodoStatus {
  PENDING = 'Pending',
  IN_PROGRESS = 'In Progress',
  COMPLETED = 'Completed',
}

@Schema({ timestamps: true })
export class Todo {
  @Prop({ required: true, minlength: 3, maxlength: 100 })
  title: string;

  @Prop({ required: false, maxlength: 500 })
  description?: string;

  @Prop({ required: false })
  image?: string;

  @Prop({ required: false, type: Date })
  date?: Date;

  @Prop({ required: true, enum: TodoStatus, default: TodoStatus.PENDING })
  status: TodoStatus;
}

export const TodoSchema = SchemaFactory.createForClass(Todo);
