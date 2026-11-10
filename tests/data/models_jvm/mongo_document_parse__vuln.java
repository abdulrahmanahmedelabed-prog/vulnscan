// expect: DF004
import com.mongodb.client.MongoCollection;
import org.bson.Document;
import javax.servlet.http.HttpServletRequest;

public class Accounts {
    private MongoCollection<Document> users;

    public Object login(HttpServletRequest hreq) {
        String user = hreq.getParameter("user");
        return users.find(Document.parse("{ user: '" + user + "' }")).first();
    }
}
