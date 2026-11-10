// expect-none: DF013
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.util.HtmlUtils;

public class Echo extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        response.getOutputStream().println("<b>" + HtmlUtils.htmlEscapeHex(request.getParameter("msg")) + "</b>");
    }
}
