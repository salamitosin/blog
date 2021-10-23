const mongoose = require("mongoose");
const express = require("express");
const router = express.Router();

router.get("/", (req, res) => {
  console.log("testing route");
  res.send("Hello World");
});

module.exports = router;
