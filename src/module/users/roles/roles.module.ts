import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { RolesService } from './roles.service';
import { RolesController } from './roles.controller';
import { JwtModule, JwtService } from '@nestjs/jwt';
import * as dotenv from 'dotenv';
import { Role, RoleSchema } from 'src/otherEntities/role.entity';
import { User, UserSchema } from '../entities/user.entity';
import { AuthService } from 'src/module/auth/auth.service';
import { UsersService } from '../users.service';
import { Otp, OtpSchema } from 'src/otherEntities/Otp.entity';

dotenv.config();

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Role.name, schema: RoleSchema },
      { name: User.name, schema: UserSchema },
      { name: Otp.name, schema: OtpSchema },
    ]),
    JwtModule.register({
      secret: process.env.JWT_SECRET_KEY,
      signOptions: { expiresIn: '24h' },
    }),
  ],
  providers: [RolesService, JwtService, AuthService, UsersService],
  controllers: [RolesController],
  exports: [RolesService, MongooseModule],
})
export class RolesModule {}
