// expect: DF005
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileInputStream;

public class Download {
    public FileInputStream open(HttpServletRequest hreq) throws Exception {
        String name = hreq.getParameter("name");
        File f = new File("/var/data", name);
        return new FileInputStream(f);
    }
}
