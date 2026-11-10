// expect: DF002
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class ToolsController : ControllerBase
{
    [HttpGet("dir")]
    public IActionResult List([FromQuery] string folder)
    {
        var psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c dir " + folder;
        Process.Start(psi);
        return Ok();
    }
}
