import javax.servlet.http.*;
public class C extends HttpServlet {
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String m = request.getParameter("m");
    Object o = C.class.getMethod(m).invoke(this);
    Object p = C.class.getMethod("toString").invoke(this);
  }
}
