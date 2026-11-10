// expect-none: DF002 DF003
const { execFileSync } = require('child_process');
exports.handler = async (event) => {
  execFileSync('convert', [String(event.multiValueQueryStringParameters.file[0]), 'out.png']);
};
