import java.io.*;
import java.util.regex.Pattern;
import javax.servlet.http.*;

public class PQ extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String q = request.getParameter("q");
        response.getWriter().println("<p>" + q + "</p>");
        response.getWriter().println("<p>" + Pattern.quote(q) + "</p>");
    }
}
