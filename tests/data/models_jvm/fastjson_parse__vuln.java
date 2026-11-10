// expect: DF006
import com.alibaba.fastjson.JSON;
import javax.servlet.http.HttpServletRequest;

public class Api {
    public Object body(HttpServletRequest hreq) {
        return JSON.parse(hreq.getParameter("data"));
    }
}
