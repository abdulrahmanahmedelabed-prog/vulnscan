// expect: DF012
import com.opensymphony.xwork2.ActionContext;
import com.opensymphony.xwork2.util.ValueStack;
import javax.servlet.http.HttpServletRequest;

public class Lookup2 {
    public Object find(HttpServletRequest hreq) {
        ValueStack valueStack = ActionContext.getContext().getValueStack();
        return valueStack.findValue(hreq.getParameter("expr"));
    }
}
