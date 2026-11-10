// expect: DF005
import javax.servlet.http.HttpServletRequest;
import java.nio.file.Files;
import java.nio.file.Path;

public class Logs {
    public Object tail(HttpServletRequest hreq) throws Exception {
        Path baseDir = Path.of("/srv/logs");
        Path p = baseDir.resolve(hreq.getParameter("log"));
        return Files.lines(p).limit(100).toList();
    }
}
