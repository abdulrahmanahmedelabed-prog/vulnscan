// expect-none: DF013
using Microsoft.AspNetCore.Mvc;

public class ItemsController : ControllerBase
{
    [HttpPost("items")]
    public IActionResult Create([FromForm] string name)
    {
        if (name.Length > 64)
        {
            return BadRequest(new { error = "name too long", name });
        }
        return Created("/items/" + name, new { name });   // JSON result (ObjectResult), not HTML
    }
}
