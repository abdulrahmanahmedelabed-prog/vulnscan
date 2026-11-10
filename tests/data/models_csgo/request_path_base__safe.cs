// expect-none: DF008
using Microsoft.AspNetCore.Mvc;

public class LanguageController : Controller
{
    // Request.PathBase is the application's configured mount point (UsePathBase), not attacker input
    public IActionResult SetLanguage()
    {
        return Redirect(Request.PathBase + "/home");
    }
}
