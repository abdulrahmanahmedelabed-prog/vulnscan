// expect: DF004
import org.springframework.jdbc.core.JdbcTemplate;
import javax.servlet.http.HttpServletRequest;

public class Export {
    private JdbcTemplate jdbc;

    public Object rows(HttpServletRequest hreq) {
        String order = hreq.getParameter("order");
        return jdbc.queryForStream("SELECT * FROM t ORDER BY " + order, (rs, i) -> rs.getString(1));
    }
}
