const fastify = require('fastify')();
const fs = require('fs');

fastify.register(require('./items'), { prefix: '/items' });

fastify.get('/download', async (request, reply) => {
  return fs.readFileSync('/srv/files/' + request.query.name);
});

fastify.route({
  method: 'POST',
  url: '/profile',
  preHandler: [fastify.authenticate],
  handler: async (request, reply) => {
    return { name: request.body.name };
  },
});

fastify.listen({ port: 3000 });
