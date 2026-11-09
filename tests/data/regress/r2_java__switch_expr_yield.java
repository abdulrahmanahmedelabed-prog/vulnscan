import javax.servlet.http.*;
import java.sql.*;
import java.util.*;
import java.io.*;
public class Y extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    String v = req.getParameter("v");
    String q = switch (req.getParameter("k")) {
      case "a" -> "SELECT * FROM t WHERE a='" + v + "'";
      case "b" -> { String w = "SELECT * FROM t WHERE b='" + v + "'"; yield w; }
      default -> "SELECT 1";
    };
    DriverManager.getConnection("x").createStatement().executeQuery(q); // SINK
  }
}
