// expect: DF014
using System.DirectoryServices;
using Microsoft.AspNetCore.Mvc;

public class DirectoryController : ControllerBase
{
    [HttpGet("people")]
    public IActionResult People([FromQuery] string user)
    {
        var searcher = new DirectorySearcher();
        searcher.Filter = "(&(objectClass=user)(sAMAccountName=" + user + "))";
        return Ok(searcher.FindOne());
    }
}
