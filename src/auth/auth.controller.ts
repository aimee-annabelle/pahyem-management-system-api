import { Controller, Post, Body } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('signup')
    @ApiOperation({ summary: 'Register a new user' })
    @ApiBody({ type: SignupDto })
    @ApiResponse({
        status: 201,
        description: 'User successfully registered',
        schema: {
            type: 'object',
            properties: {
                user: {
                    type: 'object',
                    properties: {
                        id: { type: 'string' },
                        name: { type: 'string' },
                        email: { type: 'string' },
                        role: { type: 'string' },
                        createdAt: { type: 'string' },
                        updatedAt: { type: 'string' },
                    },
                },
                access_token: { type: 'string' },
            },
        },
    })
    @ApiResponse({ status: 400, description: 'Bad request.' })
    @ApiResponse({ status: 409, description: 'User already exists.' })
    @ApiResponse({ status: 500, description: 'Internal server error.' })
    async signup(@Body() signupDto: SignupDto) {
        return await this.authService.signup(signupDto);
    }

    @Post('login')
    @ApiOperation({ summary: 'Login user' })
    @ApiBody({ type: LoginDto })
    @ApiResponse({
        status: 200,
        description: 'User successfully logged in',
        schema: {
            type: 'object',
            properties: {
                user: {
                    type: 'object',
                    properties: {
                        id: { type: 'string' },
                        name: { type: 'string' },
                        email: { type: 'string' },
                        role: { type: 'string' },
                        createdAt: { type: 'string' },
                        updatedAt: { type: 'string' },
                    },
                },
                access_token: { type: 'string' },
            },
        },
    })
    @ApiResponse({ status: 401, description: 'Invalid credentials.' })
    @ApiResponse({ status: 500, description: 'Internal server error.' })
    async login(@Body() loginDto: LoginDto) {
        return await this.authService.login(loginDto);
    }
}
