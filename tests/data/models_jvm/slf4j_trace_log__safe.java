// expect-none: DF016
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.servlet.http.HttpServletRequest;

public class Audit {
    private static final Logger auditLogger = LoggerFactory.getLogger(Audit.class);

    public void record(HttpServletRequest hreq) {
        long id = Long.parseLong(hreq.getParameter("id"));
        auditLogger.trace("login attempt for account " + id);
    }
}
