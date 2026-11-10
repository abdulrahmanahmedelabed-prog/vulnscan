// expect: DF004
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

public class StatsController : ControllerBase
{
    private readonly ShopContext _db;

    [HttpGet("count")]
    public IActionResult Count([FromQuery] string status)
    {
        var n = _db.Database.SqlQueryRaw<int>("SELECT COUNT(*) AS Value FROM Orders WHERE Status = '" + status + "'").ToList();
        return Ok(n);
    }
}
