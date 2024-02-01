
import 'dotenv/config';
import express from 'express';
import mongoose from 'mongoose';
import aws from 'aws-sdk';
import {getAuth} from 'firebase-admin/auth'
import bcrypt from 'bcrypt';
import {nanoid} from 'nanoid';
import jwt from 'jsonwebtoken'
import User from '../server/Schema/User.js';
import cors from 'cors';
import Blog from '../server/Schema/Blog.js';
import admin from 'firebase-admin'
import Notification from '../server/Schema/Notification.js'
import Comment from '../server/Schema/Comment.js'

const server = express();

const ServiceAccountKey = {
  "type": "service_account",
  "project_id": "blogging-application-b9b6d",
  "private_key_id": "d21b96109714a74337cdd9db96ac5ab902b657ab",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC6Y9D67NsyL096\nxuKMn2CH61xFSfLNzaOhMvcBsGdloEnxCJobLUeRH+9h0szd1MGzePsiAEMkFYQX\no+jV4Z9oDZOIDnk1K0cAbOzRhBEfLiKl4zkpjn8I0vV/Oyw8aniihaPVkiASr07P\n3PHAZ6fyZAlhWzwzMas1Qv1GlGe+ilJ9cWxsp5Qa6K0T2+XPg5n1lKAgyifaUWum\n089gbBbkOOiHgAntEyUzbAPsY4+udjQFcqfUHuBXWQskTccffFEJzUqSoPLTDwHg\nFKlTJeVM5FLFG2jwb7xqVs0dwrv0lYZqZuYB8S8VgX4T3JfmYOValWCtBpJCm9FA\ngKbaPpTXAgMBAAECggEAKNeDbOBmvY3pXA1ligvIUrArhVFJX3hOgR2SS2/0kCu5\n2BOa9RaMZov5X9WZp4gds65wVQh6rdb7HVUAyZEJZXsIF1mYjKKBieHUWKqYN91b\noT7zgRwk0PGs8qasMEbiTTZ8aml9FqsMWXbgEFmGTxJFjew4ej1Jdz/JEOSnAPSd\nW4lDNFX77KqVNGLdJ//6LwIHHmabnjQI0pkblp+dbeD/ytqSIoefm1MmCR5bM4Yu\njghh0D5u+pb+H3Q70pgFjLzri4YU7mw7TrFMYZCddHZBtZSU/uJmSXbC4XegWMdR\n0S0dtEJ1BNXySgD835wqxsX54CYhs2yhMJCpgta8FQKBgQDqbN5ZtAYdbg+Jla/9\nD4Zz4m9NqdmDMyMp0710NgnXrs+DqQj8igh4WEtPhvO3Ma/IHKWuYnDhl+9aU8Jk\n2E9/QHx0yY7dl9up3Udm0lrPNdG3HVc0+4bPvuUuuV42jog5Hq4Fv4Z6ZeOTISra\nnb83quvnqTBolQc/leIiBZl8BQKBgQDLizhLn0lncIpY1vlQ+d6k3gcF/5PUB+NA\nPFHHLFvhwJzSKHdNVFI4XAu1E+rcol1eFLoLklDfnO16wZTfJeeEBZRSZRirsn5o\nZ2eeokEJQOh7BIEnzKsCZyGSH5KY8oFg7pQ3s5Yr00wuIz2FQvrSog5FYLajlbRc\nYQrQiBfAKwKBgQCoQSd9/sX8zYf9WiCMY14/QqBcf7IMhuGQHdd212pNEb0DZIl8\nqJ3XsperJtM6A0GFQXpxJVqbsG8sx71YoCC+1sv9DsWpqlsRGi8rT4O6AYjaAwca\nkgV6iir4VDeYtMh1Jt4EZijhJMwoR7/4VQxvqg/ToA2MoponOy6o+Jfm+QKBgBIF\nD0TSo0L/GaBn18ateGKMLX8Ac2vwDtRfArZpXPENhlSstHMqJeVLcNXlH4PM9Asi\nNp5To8lIMVYO0Uk4J9juTYVF4ftBYCOKFAhdQPi6wFozueN2ISWjT7uKBAZ6Ya3d\nMU4FHiRfHn1vLUEg/ueq5SyLNWAiHseW58gyZDflAoGAew+wI51fiPl0BoXtjar6\nlGM+QbrSAclEs1HUDL28PZiwoAqNiQSQzRUbsP4NpvGIB9MM0XXPmYr1fNQupmqR\nxA7O1PknZvXLIXyGpvdlupK0wccxIoFSVyvOvxuaY/txbMAPgDlIPc3WEhbuCaJm\n0KK2qt4P7gppaG4tL+5W7LU=\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-7xoop@blogging-application-b9b6d.iam.gserviceaccount.com",
  "client_id": "104432578254166060525",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-7xoop%40blogging-application-b9b6d.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}
let PORT = 3000;
admin.initializeApp ({
  credential:admin.credential.cert(ServiceAccountKey)
})
let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password
server.use(express.json());
//to use middleware  json sends requests and gets respose
server.use(cors()); //enables to accept data from anywhere
mongoose.connect(process.env.DB_LOC,
    { autoIndex:true})
//setting s3 bucket

const s3 = new aws.S3({
  region:'ap-south-1',
  accessKeyId: process.env.AWS_ACCESS_KEY,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,

})

//generating url for uploading
const generateUploadURL =  async () => {
  const date = new Date();
 
  const imageName = `${nanoid()}-${date.getTime()}.jpeg`;
 return await s3.getSignedUrlPromise('putObject',{
    Bucket:'blogging-application',
    Key: imageName,
    Expires : 1000,
    ContentType : "image/jpeg"
   
  })
}
// "image/jpeg",
const verifyJWT =(req,res,next)=>{
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(" ")[1];
  if(token == null){
    return res.status(401).json({error:"No Access Token"})
  }
  jwt.verify(token,process.env.SECRET_ACCESS_KEY,(err,user)=>{
    if(err){
      return res.status(403).json({error:"Access Token is Invalid"})
    }
    req.user = user.id
    next()
  })
}


    const formatDatatoSend =(user) => {

         const access_token = jwt.sign({id: user._id},process.env.SECRET_ACCESS_KEY) 

        return {
            access_token,
            profile_img: user.personal_info.profile_img,
            username: user.personal_info.username,
            fullname: user.personal_info.fullname
        }
    }


const generateUsername = async(email)=>{
    let username = email.split("@")[0];
    let isUsernameNotUnique = await User.exists({"personal_info.username":username}).then((result)=> result)
isUsernameNotUnique ? username += nanoid().substring(0,5): "";
return username
}
//upload image url route
server.get('/get-upload-url',(req,res)=>{
  generateUploadURL().then(url => res.status(200).json({uploadURL:url}))
  .catch (err =>
    {console.log(err.message);
    return res.status(500).json({error:err.message})
  })
})

server.post("/signup",(req,res)=>{
let{fullname, email ,password} = req.body; 
//validating data from the frontend
if(fullname.length < 3)
{
   return res.status(403).json({"error":"Fullname must be at least 3 letters long"})//invalidation sts code 403
}
if(!email.length) {
    return res.status(403).json({"error":"Please Enter Email"})
}
if(!emailRegex.test(email)){
    return res.status(403).json({"error":"Email is invalid"})
}
if(!passwordRegex.test(password)){
    return res.status(403).json({"error":"Password should be 6 to 20 characters long with a numeric,1 LowerCase and 1 UpperCase Letters"})
}
bcrypt.hash(password, 10, async(err, hashed_password)=>
{
     let username = await generateUsername(email);
     let user = new User({
        personal_info: {fullname,email, password:hashed_password, username}
     })
     user.save().then((u) => {
        return res.status(200).send(formatDatatoSend(u))
     }) //to save the data in mongodb
   .catch(err => {
    if(err.code == 11000) {
        return res.status(500).json({"error" : "Email Already Exists"})
    }
    return res.status(500).json({"error":err.message})
   })
}
)

})

server.post("/signin",(req,res) =>{
    let {email, password} = req.body;
 User.findOne({"personal_info.email": email}).then((user) => {
    if(!user){
        return res.status(403).json({"error":"Email not found"});
    }
    if(!user.google_auth){
      bcrypt.compare(password,user.personal_info.password, (err,result) => {
        if(err){
            return res.status(403).json({"error": "Error occured while login please try again"});
        }
        if(!result){
            return res.status(403).json({"error":"Incorrect Password"})
        }
        else {
            return res.status(200).send(formatDatatoSend(user))
        }
       })
    }else {
      return res.status(403).json({"error": "This account was created using google.Try logging in with Google."})
    }
   
   

 })
 .catch(err => {
    console.log(err);
    return res.status(500).json({"error":"err.message"})
 })
})
//for google login
server.post('/google-auth',async(req,res)=>
{
  let {access_token} = req.body;
  getAuth().verifyIdToken(access_token).then(async(decodedUser)=>{
let {email, name, picture} = decodedUser;
picture = picture.replace('s96-c','s384-c');
let user = await User.findOne({'personal_info.email':email}).select('personal_info.fullname personal_info.username personal_info.profile_img google_auth')
.then((u) =>
{
  return u || null
}) .catch (err => {
  return res.status(500).json({ "error" :"err.message"})
})
if(user){ //login
  if(!user.google_auth){
return res.status(403).json ({"error":"This email was signed up without google. Please log in with password to access the account"})
  }

} else {
  //sign up
  let username = await generateUsername(email);
  user = new User({
    personal_info:{fullname: name,email,username},
    google_auth: true
  })
  await user.save().then((u) =>{
    user =u;
  }).catch (err =>{
    return res.status(500).json({"error": err.message})
  })
}
return res.status(200).json(formatDatatoSend(user))
  })
  .catch(err =>{
    return res.status(500).json({"error":"Failed to authenticate you with google.Try with some other google account"})
  })
})


// change password
server.post("/change-password",verifyJWT,(req,res) =>{
  let {currentPassword, newPassword} = req.body;
  if(!passwordRegex.test(currentPassword) || !passwordRegex.test(newPassword)){
    return res.status(403).json({error : "Password should be 6 to 20 characters long with a numeric, 1 lowercase and 1 uppercase letters" })
  }
  User.findOne({_id: req.user})
 .then((user) =>
 {
  if(user.google_auth){
    return res.status(403).json({error: "You can't change account's password because you logged in through google" })

  }
  bcrypt.compare(currentPassword,user.personal_info.password,(err,result)=>{
    if(err){
      return res.status(500).json({error: "Some error occured while changing the password, please try again later"})
    }
    if(!result){
      return res.status(403).json({error: "Incorrect current password" })
    }
    bcrypt.hash(newPassword,10,(err,hashed_password) => {
      User.findOneAndUpdate({ _id: req.user},{"personal_info.password": hashed_password})
      .then((u) =>{
        return res.status(200).json({status: "password changed" })
      })
        .catch(err =>
          {
            return res.status(500).json({error: 'Some error occured while saving new password, Please try agin later'})
          })
      })
    })
  })
  .catch(err => {
  console.log(err);
  res.status(500).json({error: "user not found"})
  })
 })




//latest blogs
server.post('/latest-blogs',(req,res)=>
{
  let {page} =req.body;
  let maxLimit = 5;
  Blog.find({draft:false})
  .populate("author","personal_info.profile_img personal_info.username personal_info.fullname -_id")
  .sort({"publishedAt":-1})
  .select("blog_id title des banner activity tags publishedAt -_id")
  .skip((page - 1) * maxLimit)
  .limit(maxLimit)
  .then(blogs => {
  return res.status(200).json({blogs})
}).catch(err =>
{ return res.status(500).json({error:err.message})
})
})

// for pagination
server.post("/all-latest-blogs-count", (req,res)=>{
  Blog.countDocuments({ draft:false})
  .then(count =>{
    return res.status(200).json({totalDocs:count})
  })
  .catch(err =>{
    console.log(err.message);
    return res.status(500).json({error:err.message})
  })
})

//trending blogs
server.get('/trending-blogs',(req,res)=>
{
  let maxLimit = 5;
  Blog.find({draft:false})
  .populate("author","personal_info.profile_img personal_info.username personal_info.fullname -_id")
  .sort({"activity.total_read":-1,"activity.total_likes":-1,"publishedAt" : -1})
  .select("blog_id title  publishedAt -_id")
  .limit(maxLimit)
  .then(blogs => {
  return res.status(200).json({blogs})
}).catch(err =>
{ return res.status(500).json({error:err.message})
})
})

//Searching blogs

server.post("/search-blogs",(req,res) => {
  let { tag, query, page,author,limit,eliminate_blog} = req.body;

  let findQuery;
  if(tag){
    findQuery = {tags: tag, draft: false,blog_id :{$ne:eliminate_blog} };
  }
  else if(query){
    findQuery = { draft: false, title: new RegExp(query, 'i')}
  }else if(author){
    findQuery ={ author, draft:false}
  }
  let maxLimit = limit ? limit: 5;
  Blog.find(findQuery)
  .populate("author","personal_info.profile_img personal_info.username personal_info.fullname -_id")
  .sort({"publishedAt":-1})
  .select("blog_id title des banner activity tags publishedAt -_id")
  .skip((page - 1) * maxLimit)
  .limit(maxLimit)
  .then(blogs => {
  return res.status(200).json({blogs})
}).catch(err =>
{ return res.status(500).json({error:err.message})
})
})
//search blog counts

server.post("/search-blogs-count",(req,res)=>{
  let { tag , query ,author } = req.body;
  let findQuery;
  if(tag){
    findQuery = {tags: tag, draft: false };
  }
  else if(query){
    
    findQuery = { draft: false, title: new RegExp(query, 'i')}
  }
  else if(author){
    findQuery ={ author, draft:false}
  }
  Blog.countDocuments(findQuery)
  .then(count =>{
    return res.status(200).json({totalDocs: count})
  })
  .catch(err => {
    console.log(err.message);
    return res.status(500).json({error:err.message})
  })
})
//search users
server.post("/search-users",(req,res)=>{
  let {query} = req.body;
  User.find({"personal_info.username": new RegExp(query,'i')}
  )
  .limit(50)
  .select("personal_info.fullname personal_info.username personal_info.profile_img -_id")
  .then(users =>{
    return res.status(200).json({users})
  })
  .catch(err => {
    return res.status(500).json({error:err.message})
  })
})
//user profile
server.post("/get-profile",(req,res)=>
{
  let {username} = req.body;
  User.findOne({"personal_info.username": username })
  .select("-personal_info.password -google_auth -updatedAt -blogs")
  .then(user => {
    return res.status(200).json(user)
  }).catch(err =>{
    return res.status(500).json({error: err.message})
  })
})
//updating profile image
server.post("/update-profile-img", verifyJWT,(req, res) => {
  let { url } = req.body;

  User.findOneAndUpdate({ _id: req.user}, { "personal_info.profile_img": url })
 .then(()=> {
  return res.status(200).json({ profile_img: url })
 })
 .catch(err => {
  return res.status(500).json({error: err.message})
 })
})

// updating the profile content
server.post("/update-profile", verifyJWT, (req, res) =>{
  let {username, bio, social_links} = req.body;
  let bioLimit = 150;
  if(username.length < 3){
    return res.status(403).json({error: "Username should be atleast 3 letters long"})
  }
  if(bio.length > bioLimit){
    return res.status(403).json({error: `Bio should not be more than ${bioLimit} characters`});

  }
  let socialLinksArr = Object.keys(social_links);
  try{
     for(let i = 0; i < socialLinksArr.length; i++){
      if(social_links[socialLinksArr[i]].length){
        let hostname = new URL(social_links[socialLinksArr[i]]).hostname;
        if(!hostname.includes(`${socialLinksArr[i]}.com`) && socialLinksArr[i] != 'website'){
          return res.status(403).json({error: `${socialLinksArr[i]} link is invalid. You must enter a full link`})
        }
      }
     }
  }
  catch (err){
    return res.status(500).json({error: "You must provide full social Links with http(s) included"})
  }
  let UpdateObj = {
    "personal_info.username": username,
    "personal_info.bio":bio,
    social_links
  }
  User.findOneAndUpdate({ _id: req.user}, UpdateObj,{
    runValidators:true
  })
  .then(() => {
    return res.status(200).json({username})
  })
  .catch(err =>{
    if(err.code == 11000){
      return res.status(409).json({error: "usernaem is already taken"})
    }
    return res.status(500).json({error: err.message})
  })
})

//blog creation
server.post('/create-blog',verifyJWT,(req,res)=>{
 let authorId = req.user;

 let {title,des,banner,tags,content,draft,id}= req.body;
 if(!title.length){
  return res.status(403).json({error:"You must provide a title."});

   }
 if(!draft){
  if(!des.length || des.length > 200){
    return res.status(403).json({error:"You must provide blog description under 200 characters"});
  
   }
  if(!banner.length){
    return res.status(403).json({error:"You must provide blog banner to publish it"});
  
  } 
  if(!content.blocks.length){
    return res.status(403).json({error:"There must be some blog content to publish it"});
  }
  if(!tags.length || tags.length > 10){
    return res.status(403).json({error:"The blog should contain tags it can be maximum of 10"});
  }

 }

tags = tags.map(tag => tag.toLowerCase());
let blog_id = id || title.replace(/[^a-zA-Z0-9]/g,' ').replace(/\s+/g,"-").trim() + nanoid();
if(id){
  Blog.findOneAndUpdate({blog_id},{title,des,banner,content,tags,draft: draft ? draft : false})
  .then(() =>{
    return res.status(200).json({id: blog_id });
  })
  .catch(err =>{
    return res.status(500).json({error:err.msg})
  })

}
else{
let blog =new Blog ({
  title,des,banner,content,tags,author: authorId, blog_id,draft: Boolean(draft)
})
blog.save().then(blog => {
  let incrementVal = draft ? 0:1;
  User.findOneAndUpdate({_id:authorId},{$inc :{"account_info.total_posts":incrementVal},$push: {
    "blogs":blog._id
  }}).then(user => {
    return res.status(200).json({id:blog.blog_id})
  }).catch(err => {
    return res.status(500).json({error:"Failed to update total posts number"})
  })
  .catch(err => {
    return res.status(500).json({error:err.msg})
  })
})
}

})
//Blog -page

server.post("/get-blog",(req,res) =>{
  let {blog_id,draft,mode} = req.body;
  let incrementVal = mode != 'edit' ? 1 : 0;
  Blog.findOneAndUpdate({blog_id},{$inc: {"activity.total_reads": incrementVal}})
  .populate("author","personal_info.fullname personal_info.username personal_info.profile_img")
  .select("title des content banner activity publishedAt blog_id tags")
  .then(blog => {
    User.findOneAndUpdate({"personal_info.username":blog.author.personal_info.username},{
      $inc : {"account_info.total_reads" : incrementVal}
    }).catch(err => {
      return res.status(500).json({error:err.message})
    })
    return res.status(200).json({blog});
  }).catch (err=>{
    return res.status(500).json ({error:err.message})
  })
  if(Blog.draft && !draft){ // if error occurs change Blog to blog timpstamp 1:49:00
    return res.status(500).json({error:'You cannot access draft blogs'})
  }

})

// likes
server.post("/like-blog",verifyJWT,(req,res) => {
  let user_id =req.user;
  let{ _id, isLikedByUser} = req.body;
  let incrementVal = !isLikedByUser ? 1 : -1;
  Blog.findOneAndUpdate({ _id }, { $inc: { "activity.total_likes": incrementVal}})
  .then (blog => {
    if(!isLikedByUser){
      let like = new Notification({
        type: "like",
        blog: _id,
        notification_for: blog.author,
        user: user_id
      })
      like.save().then(notification => {
        return res.status(200).json({liked_by_user: true})
      })
    } else {
        Notification.findOneAndDelete({ user: user_id, blog: _id ,type: "like"})
        .then(data => {
          return res.status(200).json({ liked_by_user: false})
        })
        .catch (err => {
          return res.status(500).json({error: err.message});
        })
    }
  })
})
//already liked by user
server.post("/isliked-by-user",verifyJWT,(req, res) => {
  let user_id = req.user;
  let { _id } = req.body;
  Notification.exists({ user: user_id, type: "like", blog: _id
  }).then(result => {
    return res.status(200).json({ result })
  })
  .catch (err => {
    return res.status(500).json({error:err.message})
  })

})
//comment
// server.post("/add-comment",verifyJWT,(req, res) => {
//   let user_id = req.user;
//   let{ _id, comment, blog_author} = req.body;
//   if(!comment.length){
//     return res.status(403).json({error: 'write Something to leave a comment'})
//   }
//   // creating  a comment doc
//   let commentObj = new Comment({
//     blog_id: _id, blog_author, comment, commented_by: user_id
//   })
//   commentObj.save().then(commentFile => {
//     let {comment, commentedAt, children } = commentFile;
//     Blog.findOneAndUpdate({ _id},{ $push: {"comments": commentFile._id}, $inc : {"activity.total_comments": 1}, "activity.total_parent_comments": 1})
//     .then(blog => { console.log ('New comment created')});
//      let notificationObj ={
//       type: "comment",
//       blog: _id,
//       notification_for: blog_author,
//       user: user_id,
//       comment: commentFile._id
//      }
//      new Notification(notificationObj).save().then(notification => console.log('new notification created'));

//      return res.status(200).json({
//       comment, commentedAt, _id: commentFile._id, user_id, children
//      })
//   })
//comment
server.post("/add-comment", verifyJWT, (req, res) => {
  let user_id = req.user;
  let { _id, comment, blog_author , replying_to, notification_id } = req.body;

  // Add validation to check if required fields are provided
  if (!_id || !comment || !blog_author) {
    return res.status(400).json({ error: 'Required fields are missing' });
  }

  if (!comment.length) {
    return res.status(403).json({ error: 'Write something to leave a comment' });
  }

  let commentObj = {
    blog_id: _id,
    blog_author,
    comment,
    commented_by: user_id
  };
  if(replying_to){
    commentObj.parent = replying_to;
    commentObj.isReply = true;
  }
  new Comment(commentObj).save().then( async commentFile => {
    let { comment, commentedAt, children } = commentFile;
    Blog.findOneAndUpdate({ _id }, { $push: { "comments": commentFile._id }, $inc: { "activity.total_comments": 1 ,"activity.total_parent_comments": replying_to ? 0 : 1}  })
      .then(blog => {
        console.log('New comment created');
      });

    let notificationObj = {
      type: replying_to ? "reply" : "comment",
      blog: _id,
      notification_for: blog_author,
      user: user_id,
      comment: commentFile._id
    };
    if(replying_to){
      notificationObj.replied_on_comment = replying_to;
      await Comment.findOneAndUpdate({ _id: replying_to },{ $push: { children: commentFile._id }})
      .then(replyingToCommentDoc => {notificationObj.notification_for = replyingToCommentDoc.commented_by})
     if(notification_id){
      Notification.findOneAndUpdate({_id: notification_id}, {reply: commentFile._id})
      .then(notification => console.log('notification updated'))
    }
    }

    new Notification(notificationObj).save().then(notification => console.log('New notification created'));

    return res.status(200).json({
      comment, commentedAt, _id: commentFile._id, user_id, children
    });
  }).catch(err => {
    console.error(err.message);
    return res.status(500).json({ error: err.message });
  });
});
// getting comments
server.post("/get-blog-comments",(req, res)=>{
  let {blog_id, skip} = req.body;
  let maxLimit = 5;
  Comment.find({blog_id ,isReply: false})
  .populate("commented_by", "personal_info.username personal_info.fullname personal_info.profile_img")
   .skip(skip)
   .limit(maxLimit)
   .sort({
    'commentedAt': -1
   })
   .then(comment =>{
    console.log(comment,blog_id,skip)
    return res.status(200).json(comment);
   })
   .catch(err =>{
    console.log(err.message);
    return res.status(500).json({error: err.message})
   })
})
//for replying to comments
server.post("/get-replies",(req,res) =>{
  let {_id,skip} = req.body;
  let maxLimit = 5;
  Comment.findOne({_id})
  .populate({
    path: "children",
    options:{
      limit: maxLimit,
      skip: skip,
      sort: { 'commentedAt': -1}
    },
    populate:{
      path: 'commented_by',
      select:"personal_info.profile_img personal_info.fullname personal_info.username"
    },
    select: "-blog_id -updatedAt"
  })
  .select('children')
  .then(doc =>{
    return res.status(200).json({replies: doc.children})
  }).catch(err => {
    return res.status(500).json({error: err.message})
  })
})
const deleteComments = (_id ) => {
   Comment.findOneAndDelete({ _id })
   .then(comment =>{
    if(comment.parent){
      Comment.findOneAndUpdate({ _id: comment.parent},{ $pull: {children: _id }})
      .then(data => console.log ('Comment deleted form parent'))
      .catch(err => console.log(err));
    }
    Notification.findOneAndDelete({comment: _id})
    .then(notification => console.log('comment notification deleted'))
    Notification.findOneAndUpdate({reply: _id},{$unset:{reply :1}}).then(notification => console.log('reply notification deleted'))
    Blog.findOneAndUpdate({_id: comment.blog_id},{$pull: {comments: _id}, $inc: { "activity.total_comments" : -1 }, "activity.total_parent_comments": comment.parent ? 0 : -1})
    .then(blog =>{
      if(comment.children.length){
        comment.children.map(replies => {
          deleteComments(replies)
        })
      }
    })
  }).catch(err => {console.log(err.message);})
}
//to delete comments
server.post("/delete-comment", verifyJWT, (req,res) => {
  let user_id = req.user;
  let { _id } = req.body;
  Comment.findOne({ _id })
  .then(comment => {
    if( user_id == comment.commented_by || user_id == comment.blog_author ){
      deleteComments( _id )
      return res.status(200).json({status: 'The Comment is Deleted'});

    }else {
      return res.status(403).json({error: "You can not delete this comment"})
    }
  })
})


server.get("/new-notification", verifyJWT,(req, res)=>{
  let user_id = req.user;
  Notification.exists({notification_for: user_id, seen: false, user:{ $ne: user_id}})
  .then(result =>{
    if(result){
      return res.status(200).json({new_notification_available: true})

    }
    else{
      return res.status(200).json({new_notification_available: false})

    }
  })
  .catch(err =>{
    console.log(err.message);
    return res.status(500).json({error: err.message})
  })

})
server.post("/notifications", verifyJWT, (req,res)=>{
  let user_id = req.user;
  let { page, filter, deletedDocCount} = req.body;
  let maxLimit =10;
  let findQuery ={notification_for: user_id, user: {$ne: user_id}};
  let skipDocs =( page - 1 ) * maxLimit;
  if(filter != 'all'){
    findQuery.type =filter;
  }
  if(deletedDocCount){
    skipDocs -= deletedDocCount;
  }
  Notification.find(findQuery)
  .skip(skipDocs)
  .limit(maxLimit)
  .populate("blog", "title blog_id")
  .populate("user", "personal_info.fullname personal_info.username personal_info.profile_img")
  .populate("comment", "comment")
  .populate("replied_on_comment", "comment")
  .populate("reply", "comment")
  .sort({createdAt: -1})
  .select("createdAt type seen reply")
  .then(notifications =>{
    Notification.updateMany(findQuery,{seen: true})
    .skip(skipDocs)
    .limit(maxLimit)
    .then(()=> console.log('notification seen'));
    return res.status(200).json({notifications});
  })
  .catch(err =>{
    console.log(err.message);
    return res.status(500).json({error: err.message});

  })

 })

 server.post("/all-notifications-count", verifyJWT,(req, res)=>{
  let user_id = req.user;
  let {filter} = req.body;
  let findQuery ={notification_for: user_id, user: {$ne: user_id}}
  if(filter != 'all'){
    findQuery.type =filter;
  }
   Notification.countDocuments(findQuery)
   .then(count => {
    return res.status(200).json({totalDocs:count})
   })
   .catch(err =>{
    return res.status(500).json({error: err.message})
   })
 })

 //user written blog access
 server.post("/user-written-blogs", verifyJWT, (req, res) => {
  let user_id = req.user;
  let { page, draft, query, deletedDocCount} = req.body;
  let maxLimit = 5;
  let skipDocs = (page - 1) * maxLimit;
  if(deletedDocCount){
    skipDocs -= deletedDocCount;
  }
  Blog.find({author: user_id, draft, title: new RegExp(query, 'i') })
  .skip(skipDocs)
  .limit(maxLimit)
  .sort({ publishedAt: -1 })
  .select("title banner publishedAt blog_id activity des draft -_id")
  .then(blogs => {
    return res.status(200).json({ blogs })
  })
  .catch(err => {
    return res.status(500).json({error: err.message});
  })
 })
 //user written blog
 server.post("/user-written-blogs-count", verifyJWT,(req, res)=>{
  let user_id = req.user;
  let{draft, query } = req.body;
  Blog.countDocuments({author: user_id, draft, title: new RegExp(query, 'i')})
  .then(count => {
    return res.status(200).json({totalDocs: count})
  })
  .catch(err => {
    console.log(err.message);
    return res.status(500).json({error: err.message});
  })
 })
 // deleting blog from settings
 server.post("/delete-blog",verifyJWT,(req, res)=>{
  let user_id = req.user;
  let {blog_id} = req.body;
  Blog.findOneAndDelete({blog_id})
  .then(blog =>{
    Notification.deleteMany({blog: blog._id})
    .then(data => console.log('notification deleted'));
    Comment.deleteMany({blog_id: blog._id}).then(data => console.log('comments deleted'));
  User.findOneAndUpdate({_id: user_id}, {$pull: {blog:blog_id}, $inc: {"account_info.total_posts": -1}})
  .then(user => console.log('Blog Deleted'));
  return res.status(200).json({status: 'done'});

  }).catch(err =>{
    return res.status(500).json({error: err.message})
  })
 })
server.listen(PORT,()=>{
    console.log("listening on port "+ PORT)
})