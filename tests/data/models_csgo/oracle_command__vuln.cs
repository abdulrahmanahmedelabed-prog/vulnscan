// expect: DF004
using Oracle.ManagedDataAccess.Client;
using Microsoft.AspNetCore.Mvc;

public class LegacyController : Controller
{
    [HttpGet]
    public IActionResult Employee(string name, OracleConnection conn)
    {
        var cmd = new OracleCommand("SELECT * FROM EMP WHERE ENAME = '" + name + "'", conn);
        cmd.ExecuteReader();
        return View();
    }
}
