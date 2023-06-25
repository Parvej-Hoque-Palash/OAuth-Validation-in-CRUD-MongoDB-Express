require("dotenv").config();
const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const nodemon = require("nodemon");
const mongoose = require("mongoose");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
app.use(bodyParser.json());
const uri = process.env.MONGODB_URI;
mongoose
  .connect(uri, { useNewUrlParser: true })
  .then(() => console.log("Connected!"));
mongoose.connection.on("connected", function () {
  console.log("Mongoose default connection open");
});
//If the connection throws an error
mongoose.connection.on("error", function (err) {
  console.log("Mongoose default connection error");
});
const userSchema = new mongoose.Schema(
  {
    fname: String,
    lname: String,
    email: String,
    password: String,
    age: Number
  },
  {
    timestamps: true
  }
  )

  const User = mongoose.model("User", userSchema);

  //Middleware to authenticate JWT access token
  const authenticateToken = (req, res, next) =>{
    const authHeader = req.headers.authorization
    const token = authHeader && authHeader.split(' ')[1]
  //token is an array where its first element(index:0) is 'Bearer' and 2nd element(index:1) is the 'given token'
  if(!token){
    //if token is found then it is authorized, else not.
    res.status(401).json({message: 'Unauthorized!'})
    return
  }else {
    jwt.verify(token, process.env.JWT_SECRET, (err, payload) =>{
      if(err){
        res.status(401).json({message: 'Unauthorized!'})
      }else{
        req.user = payload //user taking user details where payload = user email and pass
        next()
      } 
    } )
  }
}

//API to check connection
app.get("/", (req, res) => {
  res.json({ message: "Welcome to our app" });
});
//API to create user
app.post("/users", async (req, res) => {
  try {
    const salt = await bcrypt.genSalt(10)
    const hash = await bcrypt.hash(req.body.password, salt)
    const password = hash
    const userObj = {
      fname: req.body.fname,
      lname: req.body.lname,
      email: req.body.email,
      age: req.body.age,
      password: password
    }
    const user = new User(userObj)
    await user.save();
    res.status(201).json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Something is wrong" });
  }
});

app.post('/users/login', async (req, res) => {
  try {
    const {email, password, type, refreshToken} = req.body
    if(!type){
      res.status(401).json({message: 'Type is not found'})
    }else{
      if(type == 'email'){
        await handleEmailLogin(email, res, password);
      }else{
        handleRefreshLogin(refreshToken, res);
      }
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Something is wrong" });
  }
})

//Get a user profile
app.get('/profile', authenticateToken, async (req, res) =>{
  try {
    const id = req.user.id; //used 'user' instead of 'params'
    const user = await User.findById(id);
    if (user) {
      res.json(user);
    } else {
      res.status(404).json({ message: "User not found" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Something is wrong" });
  }
})

//Get a user profile by id(Not Working yet)
app.get('/profile/:id',authenticateToken, async (req, res) => {
  try {
    const id = req.user.id;
    const user = await User.findById(id);
    if (user) {
      res.json(user);
    } else {
      res.status(404).json({ message: "User not found" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Something is wrong" });
  }
});

//API to get users
app.get('/users', async (req, res) => {
  try {
    const users = await User.find({});
    res.json(users);
  } catch (error) {
    res.status(404).json({ message: "User not found" });
  }
});

//API to get users by id
app.get('/users/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const user = await User.findById(id);
    if (user) {
      res.json(user);
    } else {
      res.status(404).json({ message: "User not found" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Something is wrong" });
  }
});
//API to edit user info
app.put("/users/:id", async (req, res) => {
  try {
    //keeping the hash password in database after edit also.
    const salt = await bcrypt.genSalt(10)
    const hash = await bcrypt.hash(req.body.password, salt)
    const password = hash
    const id = req.params.id;
    const body = req.body;
    const user = await User.findByIdAndUpdate(id, body, { new: true });
    if (user) {
      user.password = password
      res.json(user);
      user.save()
    } else {
      res.status(404).json({ message: "User not found" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Something is wrong" });
  }
});
//require('crypto').randomBytes(64).toString('hex')
//API to delete user
app.delete("/users/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const user = await User.findByIdAndDelete(id);
    if (user) {
      res.json(user);
    } else {
      res.status(404).json({ message: "User not found" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Something is wrong" });
  }
});
const port = process.env.PORT;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
function handleRefreshLogin(refreshToken, res) {
  if (!refreshToken) {
    res.status(401).json({ message: 'refreshToken is not defined' });
  } else {
    jwt.verify(refreshToken, process.env.JWT_SECRET, async (err, payload) => {
      if (err) {
        res.status(401).json({ message: 'Unauthorized' });
      } else {
        const id = payload.id;
        const user = await User.findById(id);
        if (!user) { //if user is not found
          res.status(401).json({ message: 'Unauthorized' });
        } else { //if user is found
          getUserTokens(user, res);
        }
      }
    });
  }
}

async function handleEmailLogin(email, res, password) {
  const user = await User.findOne({ email: email });
  //Checking if user email is valid
  if (!user) {
    res.status(401).json({ message: "User not found" });
  } else {
    //Checking if user password is valid
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      res.status(401).json({ message: "Wrong Password!" });
    } else {
      getUserTokens(user, res);
    }
  }
}

function getUserTokens(user, res) {
  const accessToken = jwt.sign({ email: user.email, id: user._id }, process.env.JWT_SECRET, { expiresIn: '1m' });
  const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '5m' });
  const userObj = user.toJSON();
  userObj['accessToken'] = accessToken;
  userObj['refreshToken'] = refreshToken;
  res.status(200).json(userObj);
}
