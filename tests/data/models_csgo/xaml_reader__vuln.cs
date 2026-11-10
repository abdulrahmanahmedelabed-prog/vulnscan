// expect: DF006
using System.Windows.Markup;
using Microsoft.AspNetCore.Mvc;

public class LayoutController : ControllerBase
{
    [HttpPost("layout")]
    public IActionResult Import([FromBody] string xaml)
    {
        var view = XamlReader.Parse(xaml);
        return Ok();
    }
}
