// expect-none: DF005
using System.IO;
using System.Web.Mvc;

public class DocumentsController : Controller
{
    public ActionResult Details(string file)
    {
        var text = File.ReadAllText("/srv/docs/" + Path.GetFileName(file));
        return View((object)text);
    }
}
