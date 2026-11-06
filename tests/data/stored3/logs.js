const { exec } = require('child_process');
const table = process.env.LOG_TABLE;
app.post('/log', (req, res) => { pool.query(`INSERT INTO ${table} (line) VALUES (?)`, [req.body.line]); });
app.get('/log', async (req, res) => {
  const [rows] = await pool.query('SELECT line FROM event_log');
  exec('echo ' + rows[0].line);
});
