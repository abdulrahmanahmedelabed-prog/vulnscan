// expect-none: DF004
import org.hibernate.Session;
import javax.servlet.http.HttpServletRequest;

public class Purge {
    private Session session;

    public int purge(HttpServletRequest hreq) {
        String owner = hreq.getParameter("owner");
        return session.createNativeMutationQuery("DELETE FROM drafts WHERE owner = :o").setParameter("o", owner).executeUpdate();
    }
}
