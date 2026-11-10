// expect-none: DF004
using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

public class AccountController : Controller
{
    [HttpPost]
    public IActionResult Find(string email)
    {
        using var conn = new SqlConnection("Server=.;Database=app");
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Id FROM Users WHERE Email = @email";
        cmd.Parameters.AddWithValue("@email", email);
        cmd.ExecuteScalar();
        return Ok();
    }
}
