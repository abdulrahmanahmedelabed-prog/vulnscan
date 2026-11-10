// expect-none: DF015
using System.Xml.XPath;
using Microsoft.AspNetCore.Mvc;

public class CatalogController : ControllerBase
{
    private readonly XPathNavigator _nav;

    [HttpGet("book")]
    public IActionResult Book([FromQuery] string title)
    {
        var it = _nav.Select("/catalog/book");
        return Ok(title.Length + it.Count);
    }
}
