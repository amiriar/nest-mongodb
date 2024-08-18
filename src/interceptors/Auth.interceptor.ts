import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable, from, throwError } from 'rxjs';
import { catchError, switchMap } from 'rxjs/operators';
import { AuthService } from 'src/module/auth/auth.service';
import { UsersService } from 'src/module/users/users.service';
import * as cookie from 'cookie';
import { UserDocument } from 'src/module/users/entities/user.entity';

@Injectable()
export class RefreshTokenInterceptor implements NestInterceptor {
  constructor(
    private readonly authService: AuthService,
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Promise<Observable<any>> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();

    // Parse the cookies
    const cookies = cookie.parse(request.headers.cookie || '');
    const accessToken = cookies['accessToken']; // Extract the accessToken from cookies

    if (!accessToken) {
      return throwError(() => new UnauthorizedException('Access token missing.'));
    }

    try {
      // Verify the access token
      const decodedToken = this.jwtService.verify(accessToken, {
        secret: process.env.JWT_SECRET_KEY,
      });
      request.user = decodedToken;
      return next.handle();
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        const userId = this.jwtService.decode(accessToken)['id'];

        // Retrieve the stored refresh token from the database
        return from(this.authService.getRefreshToken(userId)).pipe(
          switchMap(async (storedRefreshToken) => {
            if (!storedRefreshToken) {
              throw new UnauthorizedException('No refresh token found in the database.');
            }

            // // Validate the stored refresh token
            // const isValidRefreshToken = await this.authService.validateRefreshToken(
            //   userId,
            //   storedRefreshToken,
            // );
            // if (!isValidRefreshToken) {
            //   throw new UnauthorizedException('Invalid refresh token.');
            // }

            // Fetch the user details from the database
            const user = await this.usersService.findOne(userId) as UserDocument;

            // Generate new access and refresh tokens
            const { accessToken: newAccessToken, refreshToken: newRefreshToken } =
              await this.authService.signToken(user);

            // Update the user's refresh token in the database
            await this.authService.saveRefreshToken(userId, newRefreshToken);

            // Set the new access token in the response cookies
            response.cookie('accessToken', newAccessToken, {
              httpOnly: true,
              maxAge: 86400000, // 24 hours
            });

            // Update the request with the new user info (if needed)
            request.user = { ...user.toObject(), accessToken: newAccessToken };

            return next.handle();
          }),
          catchError((err) => {
            return throwError(() => new UnauthorizedException(err.message));
          }),
        );
      } else {
        return throwError(() => new UnauthorizedException('Access token is invalid.'));
      }
    }
  }
}
