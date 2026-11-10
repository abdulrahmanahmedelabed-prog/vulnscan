// expect-none: DF013
const fastify = require('fastify')();
const validator = require('validator');
fastify.get('/p', async (request, reply) => {
  reply.type('text/html').send('<b>' + validator.escape(request.query.n) + '</b>');
});
