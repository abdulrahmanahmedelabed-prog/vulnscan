// expect-none: DF005
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.apache.commons.io.FilenameUtils;

public class Unzip {
    public void extract(InputStream archive, File dest) throws Exception {
        try (ZipInputStream zis = new ZipInputStream(archive)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                File target = new File(dest, FilenameUtils.getName(entry.getName()));
                try (FileOutputStream out = new FileOutputStream(target)) {
                    zis.transferTo(out);
                }
            }
        }
    }
}
