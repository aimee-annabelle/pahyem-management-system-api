import { Request } from 'express';
import { UserResponse } from './user.interface';

export interface RequestWithUser extends Request {
    user: UserResponse;
}
