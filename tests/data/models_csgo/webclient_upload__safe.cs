// expect-none: DF010
using System.Net;
using Microsoft.AspNetCore.Mvc;

public class ExportController : Controller
{
    [HttpPost]
    public IActionResult Push(string target)
    {
        var wc = new WebClient();
        wc.UploadValues("https://export.example.com/push", new System.Collections.Specialized.NameValueCollection());
        return Ok(target.Length);
    }
}
