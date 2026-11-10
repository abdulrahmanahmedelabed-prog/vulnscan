// expect: DF002
using System.Management.Automation;
using Microsoft.AspNetCore.Mvc;

public class OpsController : ControllerBase
{
    [HttpPost("svc")]
    public IActionResult Restart([FromForm] string service)
    {
        using var ps = PowerShell.Create();
        ps.AddScript("Restart-Service " + service).Invoke();
        return Ok();
    }
}
