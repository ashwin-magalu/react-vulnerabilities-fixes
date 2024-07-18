const express = require("express");
const app = express();
const PORT = 8080;
const exec = require("child_process").exec;

// Buggy Code
app.get("/", (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  const appVersionFile = req.query.versionFile;
  const command = `type ${appVersionFile}`;
  exec(command, (err, output) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    res.send({ version: output });
  });
});

app.listen(PORT, () => console.log(`server started on port ${PORT}`));
