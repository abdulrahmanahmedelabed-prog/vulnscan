// expect-none: DF008
import org.springframework.http.HttpHeaders;
import javax.servlet.http.HttpServletRequest;
import java.net.URI;

public class Back {
    public HttpHeaders back(HttpServletRequest hreq) {
        HttpHeaders headers = new HttpHeaders();
        String returnTo = hreq.getParameter("returnTo");
        headers.setLocation(URI.create("/dashboard"));
        return headers;
    }
}
