require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const bcrypt = require("bcrypt");
const Joi = require("joi");
const { MongoClient, ObjectId } = require("mongodb");
const path = require("path");

const app = express();

// middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "pictures")));

// get pages form folder
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const mongoUrl = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority`;

const client = new MongoClient(mongoUrl);
let users;

async function init() {
  await client.connect();
  const db = client.db();
  users = db.collection("users");
  console.log("Connected to MongoDB");
}
init();

// Sessions
app.use(
  session({
    secret: process.env.NODE_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: mongoUrl,
    }),
    cookie: {
      maxAge: 1000 * 60 * 60, //1 hour
    },
  })
);

/*
joi for input check
*/
const signupSchema = Joi.object({
  name: Joi.string().min(1).max(50).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

/*
home page
*/
app.get("/", (req, res) => {
  res.render("index");
});

/*
sign up page
*/
app.get("/signup", (req, res) => {
  res.render("signup");
});

/*
check input for sign up and print appropriate response
*/
app.post("/signup", async (req, res) => {
  const { error, value } = signupSchema.validate(req.body);
  if (error) return res.render("error", { message: "Invalid input" });

  const { name, email, password } = value;

  const existingUser = await users.findOne({ email });
  if (existingUser)
    return res.render("error", { message: "User already exists" });

  const hashedPassword = await bcrypt.hash(password, 10);

   await users.insertOne({
      name,
      email,
      password: hashedPassword,
      role: "user", // added role
    });

    req.session.user = { name, role: "user" }; //get role

  res.redirect("/members");
});

/*
login page
*/
app.get("/login", (req, res) => {
  res.render("login");
});

/*
check login input and print appropriate response
*/
app.post("/login", async (req, res) => {
  const { error, value } = loginSchema.validate(req.body);
  if (error) return res.render("error", { message: "Invalid input" });

  const { email, password } = value;

  const user = await users.findOne({ email });
  if (!user)
    return res.render("error", { message: "No user found" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid)
    return res.render("error", { message: "Incorrect password" });

  req.session.user = { name: user.name, role: user.role}; //fix so cookie has admin/user role

  res.redirect("/members");
});

/*
actual page, gets images from pictures folder, dsiplays 1 randomly
*/
app.get("/members", (req, res) => {
  if (!req.session.user) return res.redirect("/");

  const images = ["A1.png", "A12.png", "AA.png"];

  res.render("members", {
    name: req.session.user.name,
    images: images,
    role: req.session.user.role,
  });
});

/*
admin page
*/
app.get("/admin", async (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login"); // check for login
  }

  if (req.session.user.role !== "admin") {
    return res.status(403).render("error", {
      message: "Not authorized",
    });
  }

  const allUsers = await users.find().toArray();

  res.render("admin", { users: allUsers });
});

/*
make other user admin
*/
app.get("/make-admin/:id", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).render("error", { message: "Not authorized" });
  }

  await users.updateOne(
    { _id: new ObjectId(req.params.id) },
    { $set: { role: "admin" } }
  );

  res.redirect("/admin");
});

/*
un-admin a user
*/
app.get("/remove-admin/:id", async (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).render("error", { message: "Not authorized" });
  }

  await users.updateOne(
    { _id: new ObjectId(req.params.id) },
    { $set: { role: "user" } }
  );

  res.redirect("/admin");
});



/*
kill session on logout
*/
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

/*
basic 404 page, link send back to home
*/
app.use((req, res) => {
  res.status(404).render("404");
});

/*
check if running, print port
*/
app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});