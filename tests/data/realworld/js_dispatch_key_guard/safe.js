const pages = {dashboard: loadDashboard, projects: loadProjects};
function loadDashboard(a) { return a; }
function loadProjects(a) { return a; }
function route() {
  const h = location.hash.slice(1);
  const name = h.split('?')[0] || 'dashboard';
  const page = pages[name] ? name : 'dashboard';
  pages[page](h);
  const p2 = Object.prototype.hasOwnProperty.call(pages, name) ? name : 'dashboard';
  pages[p2](h);
  const p3 = name in pages ? name : 'dashboard';
  pages[p3](h);
  const p4 = !pages[name] ? 'dashboard' : name;
  pages[p4](h);
}
window.addEventListener('hashchange', route);
