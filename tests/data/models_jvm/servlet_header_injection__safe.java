// expect-none: DF008
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URLEncoder;

public class Lang {
    public void set(HttpServletRequest hreq, HttpServletResponse response) throws Exception {
        response.setHeader("Content-Language", URLEncoder.encode(hreq.getParameter("lang"), "UTF-8"));
    }
}
