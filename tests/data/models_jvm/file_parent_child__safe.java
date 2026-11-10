// expect-none: DF005
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileInputStream;
import org.apache.commons.io.FilenameUtils;

public class Download {
    public FileInputStream open(HttpServletRequest hreq) throws Exception {
        String name = FilenameUtils.getName(hreq.getParameter("name"));
        File f = new File("/var/data", name);
        return new FileInputStream(f);
    }
}
