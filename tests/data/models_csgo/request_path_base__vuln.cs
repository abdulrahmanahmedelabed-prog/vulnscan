// expect: DF008
using Microsoft.AspNetCore.Mvc;

public class LanguageController : Controller
{
    public IActionResult SetLanguage()
    {
        return Redirect(Request.Query["returnUrl"]);
    }
}
