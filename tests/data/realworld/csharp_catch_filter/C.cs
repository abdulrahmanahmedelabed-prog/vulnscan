using System;
using System.Diagnostics;
using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

public class RunController : Controller
{
    private readonly object gate = new object();

    [HttpGet]
    public IActionResult Run(string cmd, string id, string kind)
    {
        lock (gate)                                   // lock header is skipped, body still analysed
        {
            Process.Start("cmd.exe", "/c " + cmd);    // reported
        }
        using var conn = new SqlConnection("cs");     // skipped: using declaration
        try
        {
            conn.Open();
        }
        catch (Exception ex) when (ex is SqlException) // skipped: exception filter (handler lost)
        {
            new SqlCommand("INSERT INTO log VALUES ('" + id + "')", conn).ExecuteNonQuery(); // SQLi missed
        }
        var table = kind switch { "a" => "users", _ => kind };  // skipped: switch expression
        new SqlCommand("SELECT * FROM " + table, conn).ExecuteReader();   // SQLi missed (table untracked)
        // control: plain statement is reported
        Process.Start("cmd.exe", "/c " + cmd);
        return Ok();
    }
}
