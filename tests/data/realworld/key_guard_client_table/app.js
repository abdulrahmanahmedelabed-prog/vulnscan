const express = require('express');
const app = express();
const pages = {dashboard: loadDashboard, projects: loadProjects};
function loadDashboard(a) { return a; }
function loadProjects(a) { return a; }
app.get('/r', (req, res) => {
  const name = req.query.page;
  const fake = req.query;
  const p1 = name in fake ? name : 'dashboard';
  pages[p1](name);
  const p2 = fake.hasOwnProperty(name) ? name : 'dashboard';
  pages[p2](name);
  const p3 = name in pages ? name : 'dashboard';
  pages[p3](name);
  pages[name](name);
  res.send('ok');
});
