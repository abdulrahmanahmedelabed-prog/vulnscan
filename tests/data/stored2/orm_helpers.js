const mongoose = require('mongoose');
const { exec } = require('child_process');
const Ticket = mongoose.model('Ticket', new mongoose.Schema({ subject: String }), 'support_tickets');
async function createRecord(Model, data) { return Model.create(data); }
async function loadRecord(Model, id) { return Model.findById(id); }
app.post('/t', async (req, res) => { await createRecord(Ticket, { subject: req.body.s }); });
app.get('/t', async (req, res) => {
  const t = await loadRecord(Ticket, req.params.id);
  exec('echo ' + t.subject);
});
app.get('/raw', async (req, res) => {
  const [rows] = await pool.query('SELECT subject FROM support_tickets');
  exec('echo ' + rows[0].subject);
});
