// expect: DF004
using System.Data;
using Dapper;
using Microsoft.AspNetCore.Mvc;

public class ProductsController : ControllerBase
{
    private readonly IDbConnection _connection;

    [HttpDelete("{sku}")]
    public async Task<IActionResult> Delete(string sku)
    {
        var rows = await _connection.ExecuteAsync("DELETE FROM Products WHERE Sku = '" + sku + "'");
        return NoContent();
    }
}
