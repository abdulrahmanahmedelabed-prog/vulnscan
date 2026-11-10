// expect-none: DF004
import javax.ws.rs.core.UriInfo;
import org.hibernate.Session;

public class Catalog {
    private Session session;

    public Object list(UriInfo uriInfo) {
        String name = uriInfo.getQueryParameters().getFirst("name");
        return session.createSelectionQuery("from Product where name = :n", Object.class).setParameter("n", name).list();
    }
}
