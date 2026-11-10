// expect: DF012
using System;
using Microsoft.AspNetCore.Mvc;

public class WidgetController : ControllerBase
{
    [HttpGet("widget")]
    public IActionResult Load([FromQuery] string type)
    {
        var widget = AppDomain.CurrentDomain.CreateInstanceAndUnwrap("Widgets", type);
        return Ok(widget);
    }
}
