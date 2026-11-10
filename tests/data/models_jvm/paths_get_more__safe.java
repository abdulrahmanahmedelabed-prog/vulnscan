// expect-none: DF005
import javax.servlet.http.HttpServletRequest;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Reports {
    public byte[] read(HttpServletRequest hreq) throws Exception {
        int year = Integer.parseInt(hreq.getHeader("X-Year"));
        return Files.readAllBytes(Paths.get("/srv/reports", String.valueOf(year), "summary.pdf"));
    }
}
