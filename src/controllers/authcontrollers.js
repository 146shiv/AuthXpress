import {ApiResponse} from "../utils/api-response.js";
import { asyncHandler } from "../utils/async.handler.js";
import { User } from "../models/user.models.js";
import { ApiErorr } from "../utils/api-error.js";
import { emailVerificationMailgenContent, forgotPasswordMailgenContent, sendEmail } from "../utils/mail.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const generateAccessAndRefreshTokens = async (userId) =>{
   try {
    const user = await User.findById(userId)
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken
    await user.save({validateBeforeSave:false})
    return { accessToken, refreshToken };
   } catch (error) {
        throw new ApiErorr(500,
            "something went wrong while generating the accesstoken"
        )
   }
};

const registerUser = asyncHandler(async (req, res) =>{

    const {email, password, username, role} = req.body
    console.log("BODY:", req.body);

    const existingUser=   await User.findOne({
        $or : [{email}, {username}]
    })

    console.log("FOUND:", existingUser);
    if(existingUser){
        throw new ApiErorr(409, "User with this mail or username already exists",[]);
    }

    const user=   await User.create({
        email,
        password,
        username,
        isEmailVarified : false,
    });

    const {unHashedToken, HashedToken, TokenExpiry} = 
    user.generateTemporaryToken();

    user.emailVerificationToken = HashedToken;
    user.emailVerificationExpiry  = TokenExpiry;

    await user.save({validateBeforeSave:false});

    await sendEmail({
        email : user?.email,
        subject: "please verify your email",
        mailgenContent:emailVerificationMailgenContent(
            user.username,
            `${req.protocol}://${req.get("host")}/api/v1/user/verify-email/${unHashedToken}`
        ),
    });

    const createdUser = await User.findById(user._id).select("-password -emailVerificationToken -emailVerificationExpiry -refreshToken")


    if(!createdUser){
        throw new ApiErorr(500, "Something went wrong while registering the user");
    }

    return res
    .status(201)
    .json(
        new ApiResponse(200,
            {user:createdUser},
            "User registered successfully and email has been sent to your email",
        ),
    );
});

const login = asyncHandler(async (req, res) =>{
    const {email, password, username} = req.body

    if(!email){
        throw new ApiErorr(400, "email is required");
    }

    const user = await User.findOne({email});

    if(!user){
        throw new ApiErorr(400, "user does not exists");
    }

   const isPasswordValid =  await user.isPasswordCorrect(password);

   if(!isPasswordValid){
    throw new ApiErorr(400, "password is invalid");
   }

   const {accessToken, refreshToken} = await  generateAccessAndRefreshTokens(user._id);

   const loggedInUser = await User.findById(user._id)
   .select("-password -emailVerificationToken -emailVerificationExpiry -refreshToken")

   const options  = {
        httpsOnly:true,
        secure:true
   }

   return res
   .status(200)
   .cookie("accessToken", accessToken,options)
   .cookie("refreshToken", refreshToken,options)
   .json(
        new ApiResponse(
            200,
            {
                user: loggedInUser,
                accessToken,
                refreshToken
            },
            "User logged in successfully"
        )
        
   )
});

const logoutUser = asyncHandler(async (req, res) =>{
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set:{
                refreshToken : ""
            },

        },
        {
            new  : true
        },

    );
    const options = {
        httpsOnly:true,
        secure:true
    };
    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(
            new ApiResponse(200, {}, "User logged-out successfully"));
});

const getCurrentUser = asyncHandler(async (req, res)=>{
    res
    .status(200)
    .json(
        new ApiResponse(200, req.user, "Current user fetched successfully"));
});

const emailVerification = asyncHandler(async (req, res) =>{
    const {verificationToken} = req.params

    if(!verificationToken){
        throw new ApiErorr(201, "Email verification token is missing");
    }

    const HashedToken  = crypto
    .createHash("sha256")
    .update(verificationToken)
    .digest(hex)

   const user =  await User.findOne({
        emailVerificationToken: HashedToken,
        emailVerificationExpiry: {$gt: Date.now()}
    })
    user.emailVerificationToken = undefined
    user.emailVerificationExpiry = undefined

    if(!user){
        throw new ApiErorr(400, "Token is invalid or missing")
    }
    user.isEmailVarified =  true
    await user.save({validateBeforeSave: false});

    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            {
                isEmailVarified:true
            },

            "Email is verified"
        )
        

    )
});

const resendEmailVerification = asyncHandler(async (req, res) =>{
    const user   = await User.findById(req.user?._id);

    if(!user){
        throw new ApiErorr(404, "User doesn't exists");
    }

    if(user.isEmailVarified){
        throw new ApiErorr(409, "Email is already verified");
    }

    const {unHashedToken, HashedToken, TokenExpiry} = 
    user.generateTemporaryToken();

    user.emailVerificationToken = HashedToken;
    user.emailVerificationExpiry  = TokenExpiry;

    await user.save({validateBeforeSave:false});

    await sendEmail({
        email : user?.email,
        subject: "please verify your email",
        mailgenContent:emailVerificationMailgenContent(
            user.username,
            `${req.protocol}://${req.get("host")}/api/v1/user/verify-email/${unHashedToken}`
        ),
    });

    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            {},
            "Mail has been sent to your email id"
        )
    )



});

const refreshAccessToken = asyncHandler(async (req, res) =>{
    const incomingRefreshToken = req.cookies.accessToken || req.body.accessToken

    if(!incomingRefreshToken){
        throw new ApiErorr(401, "unauthorized access");
    }

    try {
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)
        const user = await User.findById(decodedToken?._id);

        if(!user){
            throw new ApiErorr(401, "unauthorized user");
        }

        if(incomingRefreshToken !== user?.refreshToken){
            throw new ApiErorr(401, "Refresh token is expired");

        }

        const options = {
            httpsOnly: true,
            secure: true
        }
        const {accessToken, refreshToken: newRefreshToken} = generateAccessAndRefreshTokens(user._id);

        user.refreshToken = newRefreshToken;
        await user.save();

        return res
        .status(200)
        .cookie("accessToken", accessToken ,options)
        .cookie("refreshToken", newRefreshToken,options)
        .json(
            new ApiResponse(
                200,
                {accessToken, refreshToken: newRefreshToken},
                "Access token refreshed"
            )
        )

    } catch (error) {
        throw new ApiErorr(402, "Invalid refresh token")
    }

    
});

const forgetPassword = asyncHandler(async (req, res) =>{
    const {email} = req.body

    const user = await User.findOne({email})

    if(!user){
        throw new ApiErorr(404, "User does not exists", []);
    }

    const {unHashedToken, HashedToken, TokenExpiry} =
    user.generateTemporaryToken();

    user.forgotPasswordToken = HashedToken
    user.forgotPasswordExpiry = TokenExpiry

    await user.save({validateBeforeSave: false});

    await sendEmail({
        email : user?.email,
        subject: "Password reset request",
        mailgenContent:forgotPasswordMailgenContent(
            user.username,
            `${process.env.FORGOT_PASSWORD_REDIRECT_URL}
            /${unHashedToken}`
        ),
    });

    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            {},
            "Password reset email has been sent on yout email"
        )
    )
});

const resetForgotPassword = asyncHandler(async (req, res) =>{
    const {resetToken} = req.params
    const {newPassword} = req.body

    let hashedToken =crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex")

   const user =  await User.findOne({
        forgotPasswordToken: hashedToken,
        forgotPasswordExpiry: {$gt: Date.now()}
    })

    if(!user){
        throw new ApiErorr(404, "Token is invalid or expired");
    }

    user.forgotPasswordExpiry = undefined
    user.forgotPasswordToken= undefined

    user.password = newPassword
    await user.save({validateBeforeSave: false})

    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            {},
            "Password reset successfully"
        )
    )
});

const changeCurrentPassword = asyncHandler(async (req,res)=> {
    const {oldPassword, newPassword} = req.body

    const user = await User.findById(req.user?._id);
    
    const isPasswordValid = await isPasswordCorrect(oldPassword)

    if(!isPasswordValid){
        throw new ApiErorr(400, "Invalid old Password")
    }

    user.password =newPassword

    await user.save({validateBeforeSave: false});

    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            {},
            "Password changed successfully"
        )
    )
})




export 
{
    registerUser,
    login,
    logoutUser, 
    getCurrentUser, 
    emailVerification,
    resendEmailVerification,
    refreshAccessToken,
    forgetPassword,
    resetForgotPassword,
    changeCurrentPassword
};
