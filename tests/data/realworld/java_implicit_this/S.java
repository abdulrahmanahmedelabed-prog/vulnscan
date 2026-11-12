import javax.servlet.http.*;
import java.sql.*;
public class S extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        find(req.getParameter("id"));
    }
    private void find(String id) throws Exception {
        Connection c = DriverManager.getConnection("jdbc:x");
        c.createStatement().executeQuery("SELECT name FROM users WHERE id = '" + id + "'");
    }
}
