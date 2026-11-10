// expect-none: DF012
import javax.el.ELProcessor;
import javax.servlet.http.HttpServletRequest;

public class Exprs {
    public Object eval(HttpServletRequest hreq) {
        ELProcessor elp = new ELProcessor();
        elp.defineBean("input", hreq.getParameter("e"));
        return elp.eval("input.length()");
    }
}
