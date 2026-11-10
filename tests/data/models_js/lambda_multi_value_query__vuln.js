// expect: DF002
const { execSync } = require('child_process');
exports.handler = async (event) => {
  execSync('convert ' + event.multiValueQueryStringParameters.file[0] + ' out.png');
};
