// expect-none: DF006
using System.Windows.Markup;
using Microsoft.AspNetCore.Mvc;

public class LayoutController : ControllerBase
{
    private const string DefaultLayout = "<Grid xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'/>";

    [HttpPost("layout")]
    public IActionResult Import([FromBody] string title)
    {
        var view = XamlReader.Parse(DefaultLayout);
        return Ok(title.Length);
    }
}
