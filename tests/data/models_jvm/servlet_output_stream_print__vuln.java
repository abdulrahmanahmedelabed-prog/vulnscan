// expect: DF013
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Echo extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        response.getOutputStream().println("<b>" + request.getParameter("msg") + "</b>");
    }
}
