// Trap: server-side code served by mistake; its sources are not DOM sources.
const express = require("express");
const app = express();
app.get("/hello", (req, res) => {
  res.send("<p>" + req.query.name + "</p>");
});
app.listen(3000);
