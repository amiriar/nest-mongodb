import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsOptional, IsDateString, IsEnum, MinLength, MaxLength } from 'class-validator';
import { TodoStatus } from '../entities/todo.entity';

export class CreateTodoDto {
  @ApiProperty({ description: 'Title of the todo', minLength: 3, maxLength: 100 })
  @IsString()
  @MinLength(3)
  @MaxLength(100)
  title: string;

  @ApiPropertyOptional({ description: 'Description of the todo', maxLength: 500 })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  description?: string;

  @ApiPropertyOptional({ description: 'Image URL associated with the todo' })
  @IsOptional()
  @IsString()
  image?: string;

  @ApiPropertyOptional({ description: 'Due date of the todo', type: String, format: 'date-time' })
  @IsOptional()
  @IsDateString()
  date?: string;

  @ApiPropertyOptional({ description: 'Status of the todo', enum: TodoStatus })
  @IsOptional()
  @IsEnum(TodoStatus)
  status?: TodoStatus;
}
