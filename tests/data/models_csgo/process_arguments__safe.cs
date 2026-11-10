// expect-none: DF002
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class ToolsController : ControllerBase
{
    [HttpGet("log")]
    public IActionResult List([FromQuery] string count)
    {
        var psi = new ProcessStartInfo();
        psi.FileName = "git";
        psi.Arguments = "log -n " + int.Parse(count);
        Process.Start(psi);
        return Ok();
    }
}
