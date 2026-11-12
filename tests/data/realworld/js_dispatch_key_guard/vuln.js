const pages = {dashboard: loadDashboard, projects: loadProjects};
function loadDashboard(a) { return a; }
function loadProjects(a) { return a; }
const other = {};
function route() {
  const h = location.hash.slice(1);
  const name = h.split('?')[0] || 'dashboard';
  const page = other[name] ? name : 'dashboard';
  pages[page](h);
  const p2 = name ? name : 'dashboard';
  pages[p2](h);
}
window.addEventListener('hashchange', route);
