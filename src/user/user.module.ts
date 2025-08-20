import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { PrismaModule } from '../../prisma/prisma.module';
import { AuthGuard } from '../common/guards/auth.guard';
import { RolesGuard } from '../common/guards/roles.guard';

@Module({
    imports: [PrismaModule, JwtModule],
    controllers: [UserController],
    providers: [UserService, AuthGuard, RolesGuard],
})
export class UserModule {}
