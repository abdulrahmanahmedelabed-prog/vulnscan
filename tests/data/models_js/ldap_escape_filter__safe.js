// expect-none: DF014
const ldap = require('ldapjs');
const { filter } = require('ldap-escape');
const client = ldap.createClient({ url: 'ldap://dir' });
module.exports = (req, res) => {
  client.search('ou=people,dc=x', filter`(uid=${req.query.user})`, (err, r) => res.end());
};
