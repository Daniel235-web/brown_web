import {ObjectType, Field} from "@nestjs/graphql";
import { User } from "../user/user.model";

@ObjectType()
export class ErrorType {
    @Field()
    messages: string;

    @Field({nullable: true})
    code?: string;

}
@ObjectType()
export class ResgisterResponse{
    @Field(() => User, {nullable: true})// assuming User is anther objectType you have
    user?: User

    @Field(() => ErrorType, {nullable: true})
    error?: ErrorType;
}

@ObjectType()
export class LoginResponse {
    @Field(() => User)
    user: User;

    @Field(() => ErrorType, {nullable:true})
    error?: ErrorType;
}


