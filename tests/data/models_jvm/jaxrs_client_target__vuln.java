// expect: DF010
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.servlet.http.HttpServletRequest;

public class Fetch {
    public String get(HttpServletRequest hreq) {
        Client client = ClientBuilder.newClient();
        return client.target(hreq.getParameter("url")).request().get(String.class);
    }
}
