// expect: DF005
import org.springframework.web.multipart.MultipartFile;
import javax.servlet.http.HttpServletRequest;
import java.nio.file.Path;

public class Attach {
    public void save(HttpServletRequest hreq, MultipartFile file) throws Exception {
        Path root = Path.of("/srv/uploads");
        Path dest = root.resolve(hreq.getParameter("dir"));
        file.transferTo(dest);
    }
}
