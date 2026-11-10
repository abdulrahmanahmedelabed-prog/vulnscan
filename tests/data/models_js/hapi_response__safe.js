// expect-none: DF013
const he = require('he');
const handler = (request, h) => h.response('<h1>' + he.encode(request.query.name) + '</h1>');
module.exports = { method: 'GET', path: '/x', handler };
