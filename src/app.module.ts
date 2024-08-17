import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { MongooseModule } from "@nestjs/mongoose";
import { UsersModule } from './module/users/users.module';
import * as dotenv from 'dotenv'
dotenv.config()

@Module({
  imports: [MongooseModule.forRoot(process.env.MONGO_CONNECTION_STRING), UsersModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
