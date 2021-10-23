const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");

// Set up the express app
const app = express();

// Middlewares
app.use(express.json());
app.use(cors());

const db = require("./config/db.config").url;
mongoose
  .connect(db, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to the database!");
  })
  .catch((err) => {
    console.log("Cannot connect to the database!", err);
    process.exit();
  });

//Routes
app.use("/", require("./routes/default"));
app.use("/", require("./routes/post"));
app.use("/", require("./routes/auth"));
app.use("/", require("./routes/user"));
//app.use("/user", require("./routes/user"));
//app.use("/product", require("./routes/product"));

// Start Application
app.listen(8081, console.log("Server Started -/-/-/-"));
