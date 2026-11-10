// expect-none: DF005
using System.IO;
using Microsoft.AspNetCore.Mvc;

public class BackupController : Controller
{
    [HttpPost]
    public IActionResult Copy(string name)
    {
        var target = "/data/backups/" + Path.GetFileName(name);
        File.Copy("/data/current.db", target);
        return Ok();
    }
}
