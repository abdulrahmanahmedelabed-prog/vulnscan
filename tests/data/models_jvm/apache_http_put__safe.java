// expect-none: DF010
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import javax.servlet.http.HttpServletRequest;

public class Webhook {
    public HttpPut build(HttpServletRequest hreq) throws Exception {
        HttpPut put = new HttpPut("https://hooks.example.com/notify");
        put.setEntity(new StringEntity(hreq.getParameter("message")));
        return put;
    }
}
