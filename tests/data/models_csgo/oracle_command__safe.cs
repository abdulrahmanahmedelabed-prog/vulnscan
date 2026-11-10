// expect-none: DF004
using Oracle.ManagedDataAccess.Client;
using Microsoft.AspNetCore.Mvc;

public class LegacyController : Controller
{
    [HttpGet]
    public IActionResult Employee(string name, OracleConnection conn)
    {
        var cmd = new OracleCommand("SELECT * FROM EMP WHERE ENAME = :name", conn);
        cmd.Parameters.Add(new OracleParameter("name", name));
        cmd.ExecuteReader();
        return View();
    }
}
