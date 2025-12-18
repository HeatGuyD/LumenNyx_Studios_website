// test.js - smallest possible Express app
const express = require("express");
const app = express();
const PORT = 3000;

app.get("/", (req, res) => {
  res.send("Hello from test server!");
});

app.listen(PORT, () => {
  console.log("Test server running on http://localhost:" + PORT);
});
