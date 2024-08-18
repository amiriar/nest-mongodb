import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseInterceptors,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { TodoService } from './todo.service';
import { CreateTodoDto } from './dto/create-todo.dto';
import { UpdateTodoDto } from './dto/update-todo.dto';
import { Todo } from './entities/todo.entity';
import * as dayjs from 'dayjs';
import * as jalaliday from 'jalaliday';
import { request } from 'express';
import { RefreshTokenInterceptor } from 'src/interceptors/Auth.interceptor';

dayjs.extend(jalaliday);

@ApiTags('todos')
@Controller('todo')
export class TodoController {
  constructor(private readonly todoService: TodoService) {}

  @Post()
  @UseInterceptors(RefreshTokenInterceptor)
  @ApiOperation({ summary: 'Create a new todo' })
  @ApiResponse({
    status: 201,
    description: 'The todo has been successfully created.',
    type: Todo,
  })
  @ApiResponse({ status: 400, description: 'Bad request' })
  create(@Body() createTodoDto: CreateTodoDto) {
    const persianDate = dayjs().calendar('jalali').format('YYYY/MM/DD HH:mm');
    // @ts-ignore
    const user = request.user.id;
    const newData = { ...createTodoDto, persianDate, user };
    return this.todoService.create(newData);
  }

  @Get()
  @ApiOperation({ summary: 'Retrieve all todos' })
  @ApiResponse({
    status: 200,
    description: 'Successfully retrieved todos.',
    type: [Todo],
  })
  findAll() {
    return this.todoService.findAll();
  }

  @Get(':id')
  @ApiOperation({ summary: 'Retrieve a specific todo by ID' })
  @ApiResponse({
    status: 200,
    description: 'Successfully retrieved the todo.',
    type: Todo,
  })
  @ApiResponse({ status: 404, description: 'Todo not found' })
  findOne(@Param('id') id: string) {
    return this.todoService.findOne(id);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update a specific todo by ID' })
  @ApiResponse({
    status: 200,
    description: 'The todo has been successfully updated.',
    type: Todo,
  })
  @ApiResponse({ status: 404, description: 'Todo not found' })
  @UseInterceptors(RefreshTokenInterceptor)
  update(@Param('id') id: string, @Body() updateTodoDto: UpdateTodoDto) {
    return this.todoService.update(id, updateTodoDto);
  }

  @Delete(':id')
  @UseInterceptors(RefreshTokenInterceptor)
  @ApiOperation({ summary: 'Delete a specific todo by ID' })
  @ApiResponse({
    status: 200,
    description: 'The todo has been successfully deleted.',
  })
  @ApiResponse({ status: 404, description: 'Todo not found' })
  remove(@Param('id') id: string) {
    return this.todoService.remove(id);
  }
}
