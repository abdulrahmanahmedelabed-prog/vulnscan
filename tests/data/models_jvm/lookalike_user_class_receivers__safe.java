// expect-none: DF012 DF006 DF004
import javax.servlet.http.HttpServletRequest;

class Shell {
    static String run(String s) { return s.trim(); }
}

class Engine {
    static int eval(String s) { return s.length(); }
}

class YamlUtil {
    static String load(String s) { return s.toUpperCase(); }
}

public class Lookalikes {
    public String go(HttpServletRequest hreq) {
        String v = hreq.getParameter("v");
        return Shell.run(v) + Engine.eval(v) + YamlUtil.load(v);
    }
}
