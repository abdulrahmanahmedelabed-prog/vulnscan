// expect: DF005
const fse = require('fs-extra');
module.exports = async (req, res) => {
  await fse.outputFile('uploads/' + req.body.name, req.body.content);
};
