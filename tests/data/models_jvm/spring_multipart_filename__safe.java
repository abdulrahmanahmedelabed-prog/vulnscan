// expect-none: DF005
import org.springframework.web.multipart.MultipartFile;
import java.io.FileOutputStream;
import org.springframework.web.bind.annotation.PostMapping;
import org.apache.commons.io.FilenameUtils;

public class Store {
    @PostMapping("/upload")
    public void save(MultipartFile upload) throws Exception {
        String name = FilenameUtils.getBaseName(upload.getOriginalFilename());
        try (FileOutputStream out = new FileOutputStream("/srv/files/" + name + ".bin")) {
            out.write(upload.getBytes());
        }
    }
}
