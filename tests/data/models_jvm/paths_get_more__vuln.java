// expect: DF005
import javax.servlet.http.HttpServletRequest;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Reports {
    public byte[] read(HttpServletRequest hreq) throws Exception {
        String report = hreq.getHeader("X-Report");
        return Files.readAllBytes(Paths.get("/srv/reports", "2024", report));
    }
}
