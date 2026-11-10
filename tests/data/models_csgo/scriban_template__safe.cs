// expect-none: DF007
using Scriban;
using Microsoft.AspNetCore.Mvc;

public class MailController : ControllerBase
{
    [HttpPost("preview")]
    public IActionResult Preview([FromForm] string name)
    {
        var template = Template.Parse("Hello {{ name }}!");
        return Ok(template.Render(name));
    }
}
