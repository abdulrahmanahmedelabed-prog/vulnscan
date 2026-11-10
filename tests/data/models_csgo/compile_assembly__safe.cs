// expect-none: DF007
using System.CodeDom.Compiler;
using Microsoft.CSharp;
using Microsoft.AspNetCore.Mvc;

public class PluginController : ControllerBase
{
    private const string Template = "public static class Plugin { public static int Run() => 42; }";

    [HttpPost("plugin")]
    public IActionResult Build([FromBody] string name)
    {
        var provider = new CSharpCodeProvider();
        var result = provider.CompileAssemblyFromSource(new CompilerParameters(), Template);
        return Ok(name.Length);
    }
}
