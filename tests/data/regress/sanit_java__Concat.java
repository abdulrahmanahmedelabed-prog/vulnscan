import java.io.*;
import javax.servlet.http.*;
import org.owasp.encoder.Encode;

public class Concat extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String a = request.getParameter("a");
        String b = request.getParameter("b");
        String s = Encode.forHtml(a) + b;
        response.getWriter().println("<p>" + s + "</p>");
    }
}
