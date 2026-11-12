import org.springframework.web.bind.annotation.*;
import java.sql.*;
import javax.validation.constraints.*;
@RestController
public class C {
  Connection conn;
  @GetMapping("/a")
  public String a(@RequestParam int id, @RequestParam String name, @RequestParam Long uid) throws Exception {
    conn.createStatement().executeQuery("SELECT * FROM t WHERE id = " + id);
    conn.createStatement().executeQuery("SELECT * FROM t WHERE uid = " + uid);
    conn.createStatement().executeQuery("SELECT * FROM t WHERE name = '" + name + "'");
    return "x";
  }
  @GetMapping("/b")
  public String b(@RequestParam @Pattern(regexp = "^[a-z]+$") String code) throws Exception {
    conn.createStatement().executeQuery("SELECT * FROM t WHERE code = '" + code + "'");
    return "x";
  }
}
