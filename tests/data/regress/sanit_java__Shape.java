import java.io.*;
import javax.servlet.http.*;

public class Shape extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String email = request.getParameter("email");
        if (!email.matches(".+@.+")) {
            return;
        }
        response.getWriter().println("<p>Welcome " + email + "</p>");
    }
}
