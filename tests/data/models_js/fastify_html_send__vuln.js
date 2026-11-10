// expect: DF013
const fastify = require('fastify')();
fastify.get('/p', async (request, reply) => {
  reply.type('text/html').send('<b>' + request.query.n + '</b>');
});
