// expect-none: DF013
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Mvc;

public class CommentsController : Controller
{
    [HttpPost]
    public IActionResult Preview(string comment)
    {
        var html = new MarkupString(HtmlEncoder.Default.Encode(comment));
        return View(html);
    }
}
