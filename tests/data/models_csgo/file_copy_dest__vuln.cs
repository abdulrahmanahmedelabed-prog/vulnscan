// expect: DF005
using System.IO;
using Microsoft.AspNetCore.Mvc;

public class BackupController : Controller
{
    [HttpPost]
    public IActionResult Copy(string name)
    {
        File.Copy("/data/current.db", Path.Combine("/data/backups", name));
        return Ok();
    }
}
