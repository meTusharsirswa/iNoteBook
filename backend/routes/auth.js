const express =require('express');
const User =require('../models/User');
const router =express.Router();
const { body, validationResult } = require('express-validator');
const bcrypt= require("bcryptjs");
var jwt = require('jsonwebtoken');
var fetchuser =require('../middlleware/fetchuser')

const JWT_SECRET='Tusharisagoodb$oy';


// ROUTE 1 : Create a user using Post "/api/auth/createuser".Dosn't require Auth
   router.post('/createuser',[
      body('name','Enter a valid name').isLength({ min: 3 }),
      body('email','Enter a valid email').isEmail(),           
      body('password','Password must be at least 5 words').isLength({ min: 5 }),
         ], async (req,res)=>{
            let success =false;
         // if there are errors, return bad request and the errors
         const errors = validationResult(req);
         if (!errors.isEmpty()) {
           return res.status(400).json({success, errors: errors.array() });
         }  
         try {
            // Check whether the user with this email exists already
   
         let user =await User.findOne({email:req.body.email});
         if(user){
            return res.status(400).json({success,error: "Soory a user with this email already exists"})
         }
         const salt =await bcrypt.genSalt(10);
         secPass = await bcrypt.hash(req.body.password,salt);

         // create a new user
         user =await User.create({
            name: req.body.name,
            password: secPass,
            email: req.body.email,
          });
          const data ={
            user:{
               id:user.id
            }
          }


          const authtoken =jwt.sign(data,JWT_SECRET);
         //  res.json(user)
               success=true;
         res.json({success,authtoken})
         
      } catch (error) {
         console.log(error.message);
         res.status(500).send("Internal server Error")
      }

        
} )

// ROUTE 2 : Authenticate a User  using Post "/api/auth/login".Dosn't require Auth

router.post('/login',[
   body('email','Enter a valid email').isEmail(),           
   body('password','Password cannot be blank').exists(),
      ], async (req,res)=>{
         let success =false
          // if there are errors, return bad request and the errors
          const errors = validationResult(req);
          if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
          }  
          const {email,password} = req.body;

          try {

            let user =await User.findOne({email});
            if(!user){
               success=false;
               return res.status(400).json({ errors: "please try to login with correct credentials" });
            }
            const passwordCompare = await bcrypt.compare(password,user.password);
            if(!passwordCompare){
               success=false;
               return res.status(400).json({success, errors: "please try to login with correct credentials" });
            }

            const data ={
               user:{
                  id: user.id
               }
            }
            const authtoken =jwt.sign(data,JWT_SECRET);
            success =true;
            res.json({success,authtoken})
          } catch (error) {
            console.log(error.message);
            res.status(500).send("Internal server Error")
             
      }
            
          })


         //  ROUTE 3 : Get loggedin User Details using :post "/api/auth/getuser". Login required 
        
         router.post('/getuser',fetchuser, async (req,res)=>{
         try {
            
            userId =req.user.id;
            const user = await User.findById(userId).select("-password")
            res.send(user)
            
         } catch (error) {
            console.log(error.message);
            res.status(500).send("Internal server Error")
         }
      })




module.exports =router