using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

public class UsersController : Controller
{
    [HttpGet]
    public IActionResult Get(string id)
    {
        using (SqlConnection conn = new SqlConnection("cs"))
        {
            var cmd = new SqlCommand("SELECT name FROM users WHERE id = '" + id + "'", conn);
            cmd.ExecuteReader();
        }
        return Ok();
    }
}
