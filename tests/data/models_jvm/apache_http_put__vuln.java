// expect: DF010
import org.apache.http.client.methods.HttpPut;
import javax.servlet.http.HttpServletRequest;

public class Webhook {
    public HttpPut build(HttpServletRequest hreq) {
        return new HttpPut(hreq.getParameter("callback"));
    }
}
