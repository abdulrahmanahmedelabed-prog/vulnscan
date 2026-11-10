// expect-none: DF005
using System.IO;
using Microsoft.AspNetCore.Mvc;

public class LogsController : ControllerBase
{
    [HttpGet("tail")]
    public IActionResult Tail([FromQuery] string log)
    {
        var lines = File.ReadLines("/var/log/app/" + Path.GetFileName(log));
        return Ok(lines);
    }
}
