const mongoose = require("mongoose");

const postSchema = new mongoose.Schema(
  {
    title: String,
    body: String,
    tag: String,
    authorName: String,
    //authorName: { type: Schema.Types.ObjectId, ref: "author" },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Post", postSchema);
