// expect: DF008
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Lang {
    public void set(HttpServletRequest hreq, HttpServletResponse response) {
        response.setHeader("Content-Language", hreq.getParameter("lang"));
    }
}
