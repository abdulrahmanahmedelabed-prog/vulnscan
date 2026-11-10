// expect: DF002
const { exec } = require('child_process');
module.exports = async function middleware(ctx, next) {
  exec('echo ' + ctx.get('X-Trace-Id'));
  await next();
};
