// expect-none: DF004
using System.Data;
using Dapper;
using Microsoft.AspNetCore.Mvc;

public class ProductsController : ControllerBase
{
    private readonly IDbConnection _connection;
    private readonly IDeleteProductHandler _handler;

    [HttpDelete("{sku}")]
    public async Task<IActionResult> Delete(string sku)
    {
        var rows = await _connection.ExecuteAsync("DELETE FROM Products WHERE Sku = @sku", new { sku });
        var done = await _handler.ExecuteAsync(sku);   // an application command handler, not Dapper
        return NoContent();
    }
}
