module.exports = async function (fastify, opts) {
  fastify.get('/:itemId', async (request, reply) => {
    return { id: request.params.itemId };
  });

  fastify.delete('/:itemId', { onRequest: [fastify.verifyJwt] }, async (request, reply) => {
    return { deleted: request.params.itemId };
  });
};
