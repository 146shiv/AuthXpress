import {ApiResponse} from "../utils/api-response.js";
import { asyncHandler } from "../utils/async.handler.js";
/** 
const healthCheck = (req,res,next) =>{
    try {
        const user = getUserFromDB();
        res
            .status(200)
            .json(new ApiResponse(200,{
              message:  "Server is running"
            }));
    } catch (error) {
        next(err)
    }
}
*/

const healthCheck = asyncHandler(async (req,res) =>{
    res.
    status(200, 
        {
            message:"Server is still running"
        })
})
export {healthCheck};