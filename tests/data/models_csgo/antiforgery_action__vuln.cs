// expect: DF002
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class DiagnosticsController : Controller
{
    [ValidateAntiForgeryToken]
    public IActionResult Trace(string host)
    {
        Process.Start("cmd.exe", "/c tracert " + host);
        return View();
    }
}
