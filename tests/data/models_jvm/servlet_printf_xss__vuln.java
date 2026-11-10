// expect: DF013
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Hello extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        String name = request.getParameter("name");
        response.getWriter().printf("<p>Hello %s</p>", name);
    }
}
