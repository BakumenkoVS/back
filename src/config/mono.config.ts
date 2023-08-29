import {ConfigService} from '@nestjs/config'
import { TypegooseModuleOptions } from 'nestjs-typegoose'
// require ('dotenv'). config ()
// const source = process.env.MONGO_URL;

export const getMongoDbConfig = async (configService: ConfigService):Promise<TypegooseModuleOptions> =>({
    uri: configService.get('MONGO_URI')
}) 