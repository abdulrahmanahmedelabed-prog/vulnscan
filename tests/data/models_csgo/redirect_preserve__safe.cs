// expect-none: DF008
using Microsoft.AspNetCore.Mvc;

public class AuthController : Controller
{
    [HttpPost]
    public IActionResult SignIn(string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl))
        {
            return RedirectPreserveMethod(returnUrl);
        }
        return RedirectPreserveMethod("/");
    }
}
