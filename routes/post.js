const mongoose = require("mongoose");
const express = require("express");
const router = express.Router();
const Post = require("../models/Post");

// Get All Post
router.get("/post", (req, res) => {
  Post.find()
    .then((data) => {
      res.send(data);
    })
    .catch((err) => {
      res.status(500).send({
        message: err.message || "Some error occurred",
      });
    });
});

// Get Single Post
router.get("/post/:id", (req, res) => {
  const id = req.params.id;
  Post.findOne({ _id: id })
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

router.post("/post", (req, res) => {
  console.log(req.body);
  //   const title = req.body.title;
  //   const description = req.body.description;
  //   const duration = req.body.duration;
  //   const price = req.body.price;
  const { title, body, tag, authorName } = req.body;

  // Create a Post Object
  const newPost = new Post(req.body);

  // Save Post in Database
  newPost
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

// Edit Single Post
router.put("/post/:id", (req, res) => {
  const id = req.params.id;
  Post.findOneAndUpdate({ _id: id }, req.body)
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

// Delete Single Post
router.delete("/post/:id", (req, res) => {
  const id = req.params.id;
  Post.findOneAndDelete({ _id: id })
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
