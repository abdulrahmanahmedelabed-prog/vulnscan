// expect-none: DF004
exports.stats = async (req, res, coll) => {
  await coll.mapReduce('function() { emit(this.k, 1); }', 'function(k, v) { return Array.sum(v); }', { out: 'x' });
};
