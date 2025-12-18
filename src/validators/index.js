import { body } from "express-validator";


const userRegisterValidator = () => {
    return [
        body("email")
        .trim()
        .notEmpty()
        .withMessage("Email is required")
        .isEmail()
        .withMessage("Email is invalid"),

        body("username")
        .trim()
        .notEmpty()
        .withMessage("username is required")
        .isLowercase()
        .withMessage("username must be in lower case")
        .isLength({min:3})
        .withMessage("Username must be atleast 3 character long"),

        body("password")
        .trim()
        .notEmpty()
        .withMessage("password is required"),

        body("fullname")
        .optional()
        .trim()



    ]
}

const userLoginValidator = () => {
    return [
        body("email")
        .optional()
        .isEmail()
        .withMessage("email is invalid"),

        body("password")
        .notEmpty()
        .withMessage("Password is required")

    ]
}

const userChangeCurrentPasswordValidator = () =>{
    return [
        body("oldPassword").notEmpty().withMessage
        ("Old passwordis required"),
        body("newPassword").notEmpty().withMessage
        ("New passwordis required"),
    ]
}

const userForgotPasswordValidator = () =>{
    return[
        body("email")
            .notEmpty()
            .withMessage("Email is required")
            .isEmail()
            .withMessage("Email is invalid"),
    ]
}

const userResetForgotPasswordValidator = () =>{
    return [
        body("newPassword")
        .notEmpty()
        .withMessage("Password is required")
    ]
}

export {
    userRegisterValidator,
    userLoginValidator,
    userChangeCurrentPasswordValidator,
    userForgotPasswordValidator,
    userResetForgotPasswordValidator
};