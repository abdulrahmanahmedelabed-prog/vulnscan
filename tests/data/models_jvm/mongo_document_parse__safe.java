// expect-none: DF004
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import org.bson.Document;
import javax.servlet.http.HttpServletRequest;

public class Accounts {
    private MongoCollection<Document> users;

    public Object login(HttpServletRequest hreq) {
        String user = hreq.getParameter("user");
        return users.find(Filters.eq("user", user)).first();
    }
}
