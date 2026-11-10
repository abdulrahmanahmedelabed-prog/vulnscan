// expect-none: DF005
const fse = require('fs-extra');
const path = require('path');
module.exports = async (req, res) => {
  await fse.outputFile('uploads/' + path.basename(req.body.name), req.body.content);
};
