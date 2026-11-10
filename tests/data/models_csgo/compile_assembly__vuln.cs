// expect: DF007
using System.CodeDom.Compiler;
using Microsoft.CSharp;
using Microsoft.AspNetCore.Mvc;

public class PluginController : ControllerBase
{
    [HttpPost("plugin")]
    public IActionResult Build([FromBody] string source)
    {
        var provider = new CSharpCodeProvider();
        var result = provider.CompileAssemblyFromSource(new CompilerParameters(), source);
        return Ok();
    }
}
