import { Module } from '@nestjs/common';
import { TodoService } from './todo.service';
import { TodoController } from './todo.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { Todo, TodoSchema } from './entities/todo.entity';
import { AuthService } from '../auth/auth.service';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { User, UserSchema } from '../users/entities/user.entity';
import { Role, RoleSchema } from 'src/otherEntities/role.entity';
import { Otp, OtpSchema } from 'src/otherEntities/Otp.entity';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Todo.name, schema: TodoSchema },
      { name: User.name, schema: UserSchema },
      { name: Role.name, schema: RoleSchema },
      { name: Otp.name, schema: OtpSchema },
    ]),
  ],
  controllers: [TodoController],
  providers: [TodoService, AuthService, JwtService, UsersService],
})
export class TodoModule {}
