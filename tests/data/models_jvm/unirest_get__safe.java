// expect-none: DF010
import kong.unirest.Unirest;
import javax.servlet.http.HttpServletRequest;

public class Avatar {
    public Object fetch(HttpServletRequest hreq) {
        String user = hreq.getParameter("user");
        return Unirest.get("https://avatars.example.com/default.png").asBytes();
    }
}
