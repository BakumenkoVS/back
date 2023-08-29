import { IsString } from 'class-validator';

export class RefreshTokenDto {
  @IsString({
    message: 'Ты не прокинул токен либо этот токен не является строкой!',
  })
  refreshToken: string;
}
