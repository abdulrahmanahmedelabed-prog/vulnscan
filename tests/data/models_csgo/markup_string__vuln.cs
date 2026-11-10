// expect: DF013
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Mvc;

public class CommentsController : Controller
{
    [HttpPost]
    public IActionResult Preview(string comment)
    {
        var html = new MarkupString(comment);
        return View(html);
    }
}
