// expect-none: DF004
import org.springframework.jdbc.core.JdbcTemplate;
import javax.servlet.http.HttpServletRequest;

public class Export {
    private JdbcTemplate jdbc;

    public Object rows(HttpServletRequest hreq) {
        String owner = hreq.getParameter("owner");
        return jdbc.queryForStream("SELECT * FROM t WHERE owner = ?", (rs, i) -> rs.getString(1), owner);
    }
}
