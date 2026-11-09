import java.io.*;
import java.sql.*;
import javax.servlet.http.*;

public class SqlServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String id = request.getParameter("id");
        if (!id.endsWith(".png")) {
            return;
        }
        try {
            Connection c = DriverManager.getConnection("jdbc:x");
            Statement st = c.createStatement();
            st.executeQuery("SELECT * FROM t WHERE name = '" + id + "'");
        } catch (SQLException e) {}
    }
}
