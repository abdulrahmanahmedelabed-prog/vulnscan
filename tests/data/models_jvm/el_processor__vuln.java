// expect: DF012
import javax.el.ELProcessor;
import javax.servlet.http.HttpServletRequest;

public class Exprs {
    public Object eval(HttpServletRequest hreq) {
        ELProcessor elp = new ELProcessor();
        return elp.eval(hreq.getParameter("e"));
    }
}
