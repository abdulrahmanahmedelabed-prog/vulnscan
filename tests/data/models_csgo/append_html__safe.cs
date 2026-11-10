// expect-none: DF013
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc;

public class BadgeController : Controller
{
    [HttpGet]
    public IActionResult Show(string label)
    {
        var builder = new HtmlContentBuilder();
        builder.AppendHtml("<span class='badge'>");
        builder.Append(label);
        builder.AppendHtml("</span>");
        return View(builder);
    }
}
