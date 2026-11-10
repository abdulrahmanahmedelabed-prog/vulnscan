// expect: DF005
import org.springframework.web.multipart.MultipartFile;
import java.io.FileOutputStream;
import org.springframework.web.bind.annotation.PostMapping;

public class Store {
    @PostMapping("/upload")
    public void save(MultipartFile upload) throws Exception {
        String name = upload.getOriginalFilename();
        try (FileOutputStream out = new FileOutputStream("/srv/files/" + name)) {
            out.write(upload.getBytes());
        }
    }
}
