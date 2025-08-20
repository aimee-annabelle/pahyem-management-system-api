import { ApiProperty } from '@nestjs/swagger';
import { Role } from '@prisma/client';
import { IsEmail, IsString, MinLength, IsNotEmpty, IsEnum, IsOptional } from 'class-validator';

export class CreateUserDto {
    @ApiProperty({
        description: 'User full name',
        example: 'John Doe',
        required: true,
    })
    @IsString({ message: 'Name must be a string' })
    @IsNotEmpty({ message: 'Name is required' })
    name: string;

    @ApiProperty({
        description: 'User email address',
        example: 'john.doe@example.com',
        required: true,
    })
    @IsEmail({}, { message: 'Please provide a valid email address' })
    @IsNotEmpty({ message: 'Email is required' })
    email: string;

    @ApiProperty({
        description: 'User password (minimum 6 characters)',
        example: 'password123',
        required: true,
        minLength: 6,
    })
    @IsString({ message: 'Password must be a string' })
    @MinLength(6, { message: 'Password must be at least 6 characters long' })
    @IsNotEmpty({ message: 'Password is required' })
    password: string;

    @ApiProperty({
        description: 'User role',
        enum: Role,
        required: false,
        default: Role.WORKER,
        example: Role.WORKER,
    })
    @IsEnum(Role, { message: 'Role must be either ADMIN or WORKER' })
    @IsOptional()
    role?: Role;
}
