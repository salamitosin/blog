const mongoose = require("mongoose");
const express = require("express");
const router = express.Router();
const User = require("../models/User");

// Get All User
router.get("/user", (req, res) => {
  User.find()
    .then((data) => {
      res.send({ success: true, message: "All User Data", data: data });
    })
    .catch((err) => {
      res.status(500).send({
        message: err.message || "Some error occurred",
      });
    });
});

// Get Single Course
router.get("/user/:id", (req, res) => {
  const id = req.params.id;
  User.findOne({ _id: id })
    .then((data) => {
      if (data) {
        res.send(data);
      } else {
        res.send("No Data Found");
      }
    })
    .catch((err) => {
      res.status(500).send({
        message: err.message || "Some error occurred",
      });
    });
});

router.post("/user", (req, res) => {
  console.log(req.body);
  //   const title = req.body.title;
  //   const description = req.body.description;
  //   const duration = req.body.duration;
  //   const price = req.body.price;
  const { email, password, author, gender, mobile } = req.body;

  // Create a Course Object
  const newUser = new User({
    email,
    password,
    author,
    gender,
    mobile,
  });

  // Save Course in Database
  // Save Note in the database
  newUser
    .save()
    .then((data) => {
      res.send(data);
    })
    .catch((err) => {
      res.status(500).send({
        message: err.message || "Some error occurred",
      });
    });
});

// Edit Single Course
router.put("/user/:id", (req, res) => {
  const id = req.params.id;
  User.findOneAndUpdate({ _id: id }, req.body)
    .then((data) => {
      if (data) {
        res.send(data);
      } else {
        res.send("No Data Found");
      }
    })
    .catch((err) => {
      res.status(500).send({
        message: err.message || "Some error occurred",
      });
    });
});

// Delete Single Course
router.delete("/user/:id", (req, res) => {
  const id = req.params.id;
  User.findOneAndDelete({ _id: id })
    .then((data) => {
      if (data) {
        res.send(data);
      } else {
        res.send("No Data Found");
      }
    })
    .catch((err) => {
      res.status(500).send({
        message: err.message || "Some error occurred",
      });
    });
});

module.exports = router;
