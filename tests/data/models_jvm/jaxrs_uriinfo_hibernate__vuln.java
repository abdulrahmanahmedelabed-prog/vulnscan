// expect: DF004
import javax.ws.rs.core.UriInfo;
import org.hibernate.Session;

public class Catalog {
    private Session session;

    public Object list(UriInfo uriInfo) {
        String sort = uriInfo.getQueryParameters().getFirst("sort");
        return session.createSelectionQuery("from Product order by " + sort, Object.class).list();
    }
}
