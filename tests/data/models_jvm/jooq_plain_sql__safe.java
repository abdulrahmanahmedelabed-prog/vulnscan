// expect-none: DF004
import org.jooq.DSLContext;
import javax.servlet.http.HttpServletRequest;

public class Users {
    private DSLContext dsl;

    public Object find(HttpServletRequest hreq) {
        String name = hreq.getParameter("name");
        return dsl.fetch("SELECT * FROM users WHERE name = ?", name);
    }
}
