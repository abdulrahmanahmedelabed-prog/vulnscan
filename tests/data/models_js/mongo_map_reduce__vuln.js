// expect: DF004
exports.stats = async (req, res, coll) => {
  await coll.mapReduce(req.body.map, 'function(k, v) { return Array.sum(v); }', { out: 'x' });
};
