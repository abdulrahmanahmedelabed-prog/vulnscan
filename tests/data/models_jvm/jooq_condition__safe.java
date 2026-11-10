// expect-none: DF004
import org.jooq.impl.DSL;
import org.jooq.Condition;
import javax.servlet.http.HttpServletRequest;

public class Conds {
    public Condition where(HttpServletRequest hreq) {
        return DSL.condition("status = ?", hreq.getParameter("status"));
    }
}
