import { Injectable , UnauthorizedException, BadRequestException, InternalServerErrorException} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from "../prisma.service";
import * as bcrypt from 'bcrypt';
import { Request, Response } from 'express';
import { User } from '@prisma/client';
import { ConfigService } from '@nestjs/config';
import { LoginDto, RegisterDto } from './dto';


@Injectable()
export class AuthService {
    constructor(
        private readonly jwtService: JwtService,
        private readonly prisma: PrismaService,
        private readonly configService: ConfigService
    
    ){}


    async refreshToken(req: Request, res: Response): Promise<string> {
        const refreshToken = req.cookies["refresh_token"];
    
        if (!refreshToken) {
            throw new UnauthorizedException("Refresh token not found");
        }
    
        try {
            const payload = await this.jwtService.verify(refreshToken, {
                secret: this.configService.get<string>("REFRESH_TOKEN_SECRET"),
            });
    
            const userExists = await this.prisma.user.findUnique({
                where: { id: payload.sub }
            });
    
            if (!userExists) {
                throw new BadRequestException("User no longer exists");
            }
    
            const expiresIn = 15000; // Assuming 15 seconds for demonstration
            const expiration = Math.floor(Date.now() / 1000) + expiresIn;
    
            const accessToken = this.jwtService.sign({
                ...payload,
                exp: expiration
            }, {
                secret: this.configService.get<string>("ACCESS_TOKEN_SECRET")
            });
    
            res.cookie("access_token", accessToken, { httpOnly: true });
    
            return accessToken;
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                throw new UnauthorizedException("Refresh token has expired");
            } else if (error.name === 'JsonWebTokenError') {
                throw new UnauthorizedException("Invalid refresh token");
            } else {
                throw new InternalServerErrorException("Error refreshing token");
            }
        }
    }

    private async issueTokens(user: User, response: Response) {
        const payload = {username: user.fullname, sub: user.id};

        const accessToken = this.jwtService.sign(
            {...payload},
            {
                secret: this.configService.get<string>("ACCESS_TOKEN_SECRET"),
                expiresIn: "150sec",
            }
        )
        const refreshToken = this.jwtService.sign(payload, {
            secret: this.configService.get<string>("REFRESH_TOKEN_SECRET"),
            expiresIn: "7d",
        }); 
        response.cookie("access_token", accessToken, {httpOnly: true});
        response.cookie("refresh_token", refreshToken, {httpOnly: true })
        return {
          user
        }
    }
    async validateUser(loginDto: LoginDto) {
        const user = await this.prisma.user.findUnique({
            where: {email: loginDto.email},
        });
        if(user && (await bcrypt.compare(loginDto.password, user.password))){
            return user;
        }
        return null;
    }
       async register(registerDto: RegisterDto, response: Response) {
        const findIfuserIsAlreadyInUse = await this.prisma.user.findUnique({
            where: {email: registerDto.email},
        });
        if(findIfuserIsAlreadyInUse) {
            throw new Error ("Email already in use"); 
        }
        const hashedPassword = await bcrypt.hash(registerDto.password,10);

        const user = await this.prisma.user.create({
            data: {
                fullname: registerDto.fullname,
                password: hashedPassword,
                email: registerDto.email
            }
        });
        return this.issueTokens(user, response);
       }

       async login(loginDto: LoginDto, response: Response) {
        const user = await this.validateUser(loginDto);
        if(!user) {
            throw new Error("Invalid credentials");
        }
        return this.issueTokens(user, response);
       }
       async logout(response: Response) {
        response.clearCookie("access_token");
        response.clearCookie("refresh_token");
        return {
            message: "You have been logged out"
        }
       }
    
}
