// expect: DF007
using Jint;
using Microsoft.AspNetCore.Mvc;

public class RulesController : ControllerBase
{
    [HttpPost("eval")]
    public IActionResult Eval([FromForm] string script)
    {
        var engine = new Engine();
        engine.Execute(script);
        return Ok();
    }
}
