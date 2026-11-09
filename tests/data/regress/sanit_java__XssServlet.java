import java.io.*;
import javax.servlet.http.*;

public class XssServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String q = request.getParameter("q");
        if (q.contains("<script>")) {
            return;
        }
        response.getWriter().println("<p>" + q + "</p>");
    }
}
