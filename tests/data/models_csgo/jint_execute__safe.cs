// expect-none: DF007
using Jint;
using Microsoft.AspNetCore.Mvc;

public class RulesController : ControllerBase
{
    [HttpPost("eval")]
    public IActionResult Eval([FromForm] string input)
    {
        var engine = new Engine();
        engine.SetValue("input", input);
        engine.Execute("var size = input.length;");
        return Ok();
    }
}
