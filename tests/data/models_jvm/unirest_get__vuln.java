// expect: DF010
import kong.unirest.Unirest;
import javax.servlet.http.HttpServletRequest;

public class Avatar {
    public Object fetch(HttpServletRequest hreq) {
        return Unirest.get(hreq.getParameter("avatarUrl")).asBytes();
    }
}
