import javax.servlet.http.*;
import java.sql.*;
public class T extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        find(req.getParameter("id"));
    }
    private void find(String id) throws Exception {
        Connection c = DriverManager.getConnection("jdbc:x");
        PreparedStatement ps = c.prepareStatement("SELECT name FROM users WHERE id = ?");
        ps.setString(1, id);
        ps.executeQuery();
    }
}
