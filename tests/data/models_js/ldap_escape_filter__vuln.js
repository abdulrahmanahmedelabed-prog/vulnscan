// expect: DF014
const ldap = require('ldapjs');
const client = ldap.createClient({ url: 'ldap://dir' });
module.exports = (req, res) => {
  client.search('ou=people,dc=x', '(uid=' + req.query.user + ')', (err, r) => res.end());
};
