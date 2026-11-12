const fastify = require('fastify')();
// FP: Fastify serialises returned objects as application/json and strings as text/plain
fastify.get('/users/:id', (req) => ({ route: 'user', id: req.params.id }));
fastify.post('/echo', async (request) => request.body);
fastify.get('/r', async (_, reply) => reply.code(204).send());
// TP twin: explicit HTML content type
fastify.get('/html', (req, reply) => { reply.type('text/html').send('<p>' + req.query.q + '</p>'); });
