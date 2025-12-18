import { User } from "../models/user.models.js";
import { ApiErorr } from "../utils/api-error.js";
import jwt from "jsonwebtoken"
import { asyncHandler } from "../utils/async.handler.js";


export const verifyJWT = asyncHandler(async (req, res, next) =>{

    const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer", "");

    if(!token){
        throw new ApiErorr(401, "Invalid access token");
    }

    try {
       const decodedToken =  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
       const user = await User.findById(decodedToken?._id).
       select("-password -emailVerificationToken -emailVerificationExpiry -refreshToken")
       if(!user){
            throw new ApiErorr(401, "Invalid access Token");
       }
       req.user = user
       next()
    } catch (error) {
        throw new ApiErorr(401, "Invalid access Token");
    }
});