// expect: DF005
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.Part;
import java.io.File;

public class Uploads {
    static final String UPLOAD_DIR = "/srv/uploads";

    public void store(HttpServletRequest httpServletRequest) throws Exception {
        Part part = httpServletRequest.getPart("file");
        String name = part.getSubmittedFileName();
        part.write(new File(UPLOAD_DIR, name).getPath());
    }
}
