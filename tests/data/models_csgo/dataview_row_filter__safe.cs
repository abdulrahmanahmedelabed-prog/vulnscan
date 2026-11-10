// expect-none: DF007
using System.Data;
using Microsoft.AspNetCore.Mvc;

public class GridController : Controller
{
    private readonly DataTable _table;

    [HttpGet]
    public IActionResult Filter(string minAge)
    {
        var view = new DataView(_table);
        view.RowFilter = "Age >= " + int.Parse(minAge);
        return View(view);
    }
}
