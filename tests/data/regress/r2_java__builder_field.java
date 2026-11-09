import javax.servlet.http.*;
import java.sql.*;
import java.util.*;
import java.io.*;
public class HO extends HttpServlet {
  static class Cmd {
    private final List<String> parts = new ArrayList<>();
    Cmd add(String p) { parts.add(p); return this; }
    String build() { return String.join(" ", parts); }
  }
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    Cmd c = new Cmd();
    c.add("ping");
    c.add(req.getParameter("h"));
    Runtime.getRuntime().exec(c.build()); // SINK
  }
}
