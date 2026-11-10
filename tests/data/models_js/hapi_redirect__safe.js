// expect-none: DF008
const handler = (request, h) => h.redirect('/');
module.exports = { method: 'GET', path: '/n', handler };
