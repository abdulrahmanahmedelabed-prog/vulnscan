// expect-none: DF013
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.owasp.encoder.Encode;

public class Hello extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        String name = Encode.forHtmlContent(request.getParameter("name"));
        response.getWriter().printf("<p>Hello %s</p>", name);
    }
}
