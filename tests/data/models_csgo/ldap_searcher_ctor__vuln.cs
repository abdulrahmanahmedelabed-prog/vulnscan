// expect: DF014
using System.DirectoryServices;
using Microsoft.AspNetCore.Mvc;

public class GroupsController : ControllerBase
{
    [HttpGet("groups")]
    public IActionResult Groups([FromQuery] string group)
    {
        var root = new DirectoryEntry("LDAP://dc=corp,dc=example,dc=com");
        var searcher = new DirectorySearcher(root, "(cn=" + group + ")");
        return Ok(searcher.FindAll());
    }
}
