// expect: DF005
import java.io.File
import java.io.InputStream
import java.util.zip.ZipInputStream

fun unpack(upload: InputStream, dest: File) {
    ZipInputStream(upload).use { zis ->
        var zipEntry = zis.nextEntry
        while (zipEntry != null) {
            val out = File(dest, zipEntry.name)
            out.outputStream().use { zis.copyTo(it) }
            zipEntry = zis.nextEntry
        }
    }
}
