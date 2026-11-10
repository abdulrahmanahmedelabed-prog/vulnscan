// expect: DF008
using Microsoft.AspNetCore.Mvc;

public class AuthController : Controller
{
    [HttpPost]
    public IActionResult SignIn(string returnUrl)
    {
        return RedirectPreserveMethod(returnUrl);
    }
}
