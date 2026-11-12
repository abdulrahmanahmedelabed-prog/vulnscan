// expect-none: DF005
import java.io.File
import java.io.InputStream
import java.util.zip.ZipInputStream

fun unpack(upload: InputStream, dest: File) {
    ZipInputStream(upload).use { zis ->
        var zipEntry = zis.nextEntry
        var index = 0
        while (zipEntry != null) {
            val out = File(dest, "entry-$index.bin")
            out.outputStream().use { zis.copyTo(it) }
            index += 1
            zipEntry = zis.nextEntry
        }
    }
}
