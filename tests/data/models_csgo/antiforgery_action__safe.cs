// expect-none: DF002
using System.Diagnostics;
using System.Net;
using Microsoft.AspNetCore.Mvc;

public class DiagnosticsController : Controller
{
    [ValidateAntiForgeryToken]
    public IActionResult Trace(string host)
    {
        var ip = IPAddress.Parse(host);
        Process.Start("tracert", ip.ToString());
        return View();
    }
}
