// expect-none: DF012
import groovy.util.Eval;
import javax.servlet.http.HttpServletRequest;

public class Calc {
    public Object calc(HttpServletRequest hreq) {
        // the input is only the bound value `x`, the expression is constant
        return Eval.x(hreq.getParameter("n"), "x.length() * 2");
    }
}
