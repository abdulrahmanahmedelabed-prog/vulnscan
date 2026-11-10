// expect: DF007
using Scriban;
using Microsoft.AspNetCore.Mvc;

public class MailController : ControllerBase
{
    [HttpPost("preview")]
    public IActionResult Preview([FromForm] string body)
    {
        var template = Template.Parse(body);
        return Ok(template.Render());
    }
}
