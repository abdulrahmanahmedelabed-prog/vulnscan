// expect-none: DF006
import com.alibaba.fastjson.JSON;
import javax.servlet.http.HttpServletRequest;

public class Api {
    public Object body(HttpServletRequest hreq) {
        String data = hreq.getParameter("data");
        return JSON.parse("{\"version\": 1}");
    }
}
