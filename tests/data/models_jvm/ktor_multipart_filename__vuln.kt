// expect: DF005
import io.ktor.http.content.*
import java.io.File

suspend fun saveUpload(multipart: MultiPartData) {
    multipart.forEachPart { part ->
        if (part is PartData.FileItem) {
            val fileName = part.originalFileName
            File("/srv/uploads/$fileName").writeBytes(part.streamProvider().readBytes())
        }
    }
}
