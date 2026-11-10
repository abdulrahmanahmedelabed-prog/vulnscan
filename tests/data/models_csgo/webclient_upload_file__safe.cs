// expect-none: DF010
using System.Net;
using Microsoft.AspNetCore.Mvc;

public class MirrorController : ControllerBase
{
    private readonly IStorageService _storage;

    [HttpPost("mirror")]
    public IActionResult Mirror([FromQuery] string name)
    {
        using var client = new WebClient();
        client.UploadFile("https://backup.example.com/upload", "/var/data/report.pdf");
        _storage.UploadFile(name);   // an application service, not WebClient
        return Ok();
    }
}
