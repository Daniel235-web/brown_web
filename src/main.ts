import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';
import { BadRequestException, ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors ({
    origin: "http://127.0.0.1:5173",
    credentials:true,
    //all headers that client are allowed to use
    allowedHeaders: [
      "Accept",
      "Authorization",
      "Content-Type",
      "X-Requested-With",
      "apollo-require-preflight",
    ], 
    methods: ["GET", "PUT", "POST", "DELETE", "OPTIONS"],

  })
  app.use(cookieParser());
  await app.listen(3000);
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      exceptionFactory: (errors) => {
        const formattedErrors  = errors.reduce((accumulator , error) => {
          accumulator [error.property] = Object.values(error.constraints).join(
            ",",
          );
          return accumulator;
        }, {})
        throw new BadRequestException(formattedErrors);
      },
    }

    ),
    
  );
}
bootstrap();
