import java.sql.*;
import javax.servlet.http.*;
public class Store extends HttpServlet {
    Connection conn;
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        PreparedStatement ps = conn.prepareStatement("INSERT INTO profiles (bio, city) VALUES (?, ?)");
        ps.setString(1, request.getParameter("bio"));
        ps.setString(2, "Gaza");
        ps.executeUpdate();
    }
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Statement st = conn.createStatement();
        ResultSet rs = st.executeQuery("SELECT bio FROM profiles");
        while (rs.next()) {
            response.getWriter().write("<p>" + rs.getString("bio") + "</p>");
        }
        ResultSet rs2 = st.executeQuery("SELECT city FROM profiles");
        response.getWriter().write(rs2.getString("city"));
    }
}
