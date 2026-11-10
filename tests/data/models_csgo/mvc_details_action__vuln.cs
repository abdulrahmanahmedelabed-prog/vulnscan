// expect: DF005
using System.IO;
using System.Web.Mvc;

public class DocumentsController : Controller
{
    public ActionResult Details(string file)
    {
        var text = File.ReadAllText(Path.Combine(Server.MapPath("~/App_Data"), file));
        return View((object)text);
    }
}
