// expect-none: DF005
import javax.servlet.http.HttpServletRequest;
import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.commons.io.FilenameUtils;

public class Logs {
    public Object tail(HttpServletRequest hreq) throws Exception {
        Path baseDir = Path.of("/srv/logs");
        Path p = baseDir.resolve(FilenameUtils.getName(hreq.getParameter("log")));
        return Files.lines(p).limit(100).toList();
    }
}
