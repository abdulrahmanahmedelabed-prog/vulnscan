// expect: DF007
using System.Data;
using Microsoft.AspNetCore.Mvc;

public class GridController : Controller
{
    private readonly DataTable _table;

    [HttpGet]
    public IActionResult Filter(string city)
    {
        var view = new DataView(_table);
        view.RowFilter = "City = '" + city + "'";
        return View(view);
    }
}
