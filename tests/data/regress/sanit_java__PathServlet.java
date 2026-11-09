import java.io.*;
import javax.servlet.http.*;

public class PathServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String f = request.getParameter("f");
        if (!f.startsWith("/var/www/uploads/")) {
            return;
        }
        FileInputStream in = new FileInputStream(f);
        in.read();
    }
}
