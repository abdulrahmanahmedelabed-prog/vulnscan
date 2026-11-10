// expect-none: DF005
import org.springframework.web.multipart.MultipartFile;
import javax.servlet.http.HttpServletRequest;
import java.nio.file.Path;
import java.util.UUID;

public class Attach {
    public void save(HttpServletRequest hreq, MultipartFile file) throws Exception {
        String note = hreq.getParameter("dir");
        Path root = Path.of("/srv/uploads");
        file.transferTo(root.resolve(UUID.randomUUID().toString()));
    }
}
