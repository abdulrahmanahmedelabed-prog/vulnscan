// expect: DF013
using Microsoft.AspNetCore.Mvc;

public class ItemsController : ControllerBase
{
    [HttpPost("items")]
    public string Create([FromForm] string name)
    {
        return "<p>Created " + name + "</p>";
    }
}
