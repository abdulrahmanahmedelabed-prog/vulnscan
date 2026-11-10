// expect: DF004
using NHibernate;
using Microsoft.AspNetCore.Mvc;

public class ReportController : Controller
{
    private readonly ISession _session;

    [HttpGet]
    public IActionResult Sales(string region)
    {
        var rows = _session.CreateSQLQuery("SELECT * FROM Sales WHERE Region = '" + region + "'").List();
        return View(rows);
    }
}
