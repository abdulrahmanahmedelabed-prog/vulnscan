// expect: DF012
import com.opensymphony.xwork2.ActionSupport;
import ognl.Ognl;
import org.apache.struts2.ServletActionContext;

public class EvalAction extends ActionSupport {
    public String execute() throws Exception {
        String expr = ServletActionContext.getRequest().getParameter("expr");
        Ognl.getValue(expr, new java.util.HashMap<>(), this);
        return SUCCESS;
    }
}
