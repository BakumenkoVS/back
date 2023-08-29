import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ModelType } from '@typegoose/typegoose/lib/types';
import { InjectModel } from 'nestjs-typegoose';
import { UserModel } from 'src/user/user.model';
import { AuthDto } from './dto/auth.dto';
import { hash, getSalt, compare, genSalt } from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(UserModel) private readonly UserModel: ModelType<UserModel>,
    private readonly jwtService: JwtService,
  ) {}

  async login(dto: AuthDto) {
    const user = await this.validateUser(dto);
    const tokens = await this.issueTokenPair(String(user._id));
    return {
      user: this.returnUserFields(user),
      ...tokens,
    };
  }

  async register(dto: AuthDto) {
    const oldUser = await this.UserModel.findOne({ email: dto.email });
    if (oldUser) {
      throw new BadRequestException(
        'Пользователь с таким email уже есть в системе!',
      );
    }

    const salt = await genSalt(10);

    const newUser = new this.UserModel({
      email: dto.email,
      password: await hash(dto.password, salt),
    });

    const tokens = await this.issueTokenPair(String(newUser._id));
    return {
      user: this.returnUserFields(newUser),
      ...tokens,
    };
  }

  async validateUser(dto: AuthDto): Promise<UserModel> {
    const user = await this.UserModel.findOne({ email: dto.email });
    if (!user) throw new UnauthorizedException('Пользователь не найден');

    const isValidPassword = await compare(dto.password, user.password);
    if (!isValidPassword) throw new UnauthorizedException('Не валидный пароль');

    return user;
  }

  //Создание токена пропускающего токена и рефреш токена  с их периодами жизни

  async issueTokenPair(userId: string) {
    const data = { _id: userId };

    const refreshToken = await this.jwtService.signAsync(data, {
      expiresIn: '15d',
    });

    const accessToken = await this.jwtService.signAsync(data, {
      expiresIn: '1h',
    });

    return { refreshToken, accessToken };
  }

  //Вспомогательная функция которая получает в себя модель пользователя и возвращает те поля которые нужны

  returnUserFields(user: UserModel) {
    return {
      _id: user._id,
      email: user.email,
      isAdmin: user.isAdmin,
    };
  }
}
