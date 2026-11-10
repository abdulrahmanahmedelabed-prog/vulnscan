// expect-none: DF010
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.servlet.http.HttpServletRequest;

public class Fetch {
    public String get(HttpServletRequest hreq) {
        Client client = ClientBuilder.newClient();
        int page = Integer.parseInt(hreq.getParameter("page"));
        return client.target("https://api.example.com/items").queryParam("page", page).request().get(String.class);
    }
}
