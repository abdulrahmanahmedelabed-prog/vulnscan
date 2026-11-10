// expect-none: DF008
const fastify = require('fastify')();
fastify.get('/login', async (request, reply) => {
  return reply.redirect('/dashboard');
});
