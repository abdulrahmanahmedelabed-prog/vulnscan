// expect-none: DF012
using System;
using Microsoft.AspNetCore.Mvc;

public class WidgetController : ControllerBase
{
    [HttpGet("widget")]
    public IActionResult Load([FromQuery] string type)
    {
        var name = type == "chart" ? "Widgets.Chart" : "Widgets.Table";
        var widget = AppDomain.CurrentDomain.CreateInstanceAndUnwrap("Widgets", name);
        return Ok(widget);
    }
}
