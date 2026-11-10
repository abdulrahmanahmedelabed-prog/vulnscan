// expect: DF004
using System.Data;
using Dapper;
using Microsoft.AspNetCore.Mvc;

public class ProductsController : ControllerBase
{
    private readonly IDbConnection _conn;

    [HttpGet("{sku}")]
    public async Task<IActionResult> Get(string sku)
    {
        var p = await _conn.QueryFirstOrDefaultAsync<Product>("SELECT * FROM Products WHERE Sku = '" + sku + "'");
        return Ok(p);
    }
}
