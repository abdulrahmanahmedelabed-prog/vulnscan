// expect: DF008
import org.springframework.http.HttpHeaders;
import javax.servlet.http.HttpServletRequest;
import java.net.URI;

public class Back {
    public HttpHeaders back(HttpServletRequest hreq) {
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(hreq.getParameter("returnTo")));
        return headers;
    }
}
