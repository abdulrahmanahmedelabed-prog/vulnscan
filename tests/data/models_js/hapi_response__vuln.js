// expect: DF013
const handler = (request, h) => h.response('<h1>' + request.query.name + '</h1>');
module.exports = { method: 'GET', path: '/x', handler };
