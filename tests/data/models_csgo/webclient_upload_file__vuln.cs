// expect: DF010
using System.Net;
using Microsoft.AspNetCore.Mvc;

public class MirrorController : ControllerBase
{
    [HttpPost("mirror")]
    public IActionResult Mirror([FromQuery] string target)
    {
        using var client = new WebClient();
        client.UploadFile(target, "/var/data/report.pdf");
        return Ok();
    }
}
