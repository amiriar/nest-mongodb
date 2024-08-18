import { Controller, Get, Post, Body, Param, UseInterceptors } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { CreateUserDto } from './dto/create-user.dto';
import { UsersService } from './users.service';
import { User } from './entities/user.entity';
import * as dayjs from 'dayjs';
import * as jalaliday from 'jalaliday';
import { RefreshTokenInterceptor } from 'src/interceptors/Auth.interceptor';
dayjs.extend(jalaliday);

@ApiTags('users')
@Controller('users')
export class UsersController {
  constructor(private readonly userService: UsersService) {}

  // @Post()
  // @ApiOperation({ summary: 'Create a new user' })
  // @ApiResponse({ status: 201, description: 'User successfully created.', type: User })
  // @ApiResponse({ status: 400, description: 'Invalid input.' })
  // async create(@Body() createUserDto: CreateUserDto): Promise<User> {
  //   const madeIn = dayjs().calendar('jalali').format('YYYY/MM/DD HH:mm');
  //   return this.userService.createUser(createUserDto.phoneNumber, madeIn);
  // }

  @Get()
  @UseInterceptors(RefreshTokenInterceptor)
  @ApiOperation({ summary: 'Get all users' })
  @ApiResponse({ status: 200, description: 'List of all users.', type: [User] })
  async findAll(): Promise<User[]> {
    return this.userService.findAll();
  }

  @Get(':id')
  @UseInterceptors(RefreshTokenInterceptor)
  @ApiOperation({ summary: 'Get user by ID' })
  @ApiResponse({ status: 200, description: 'The found user.', type: User })
  @ApiResponse({ status: 404, description: 'User not found.' })
  async findOne(@Param('id') id: string): Promise<User> {
    return this.userService.findOne(id);
  }
}
