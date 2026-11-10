// expect: DF008
const handler = (request, h) => h.redirect(request.query.next);
module.exports = { method: 'GET', path: '/n', handler };
