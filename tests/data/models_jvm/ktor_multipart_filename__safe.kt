// expect-none: DF005
import io.ktor.http.content.*
import java.io.File
import java.util.UUID

suspend fun saveUpload(multipart: MultiPartData) {
    multipart.forEachPart { part ->
        if (part is PartData.FileItem) {
            val fileName = part.originalFileName
            File("/srv/uploads/" + UUID.randomUUID()).writeBytes(part.streamProvider().readBytes())
        }
    }
}
