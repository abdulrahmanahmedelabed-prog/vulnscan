// expect: DF004
import org.hibernate.Session;
import javax.servlet.http.HttpServletRequest;

public class Purge {
    private Session session;

    public int purge(HttpServletRequest hreq) {
        String table = hreq.getParameter("table");
        return session.createNativeMutationQuery("DELETE FROM " + table).executeUpdate();
    }
}
