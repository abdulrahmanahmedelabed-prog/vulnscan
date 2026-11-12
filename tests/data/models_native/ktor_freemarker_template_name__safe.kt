// expect-none: DF007
import io.ktor.server.application.*
import io.ktor.server.freemarker.FreeMarkerContent
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Route.pages() {
    get("/pages/{page}") {
        val page = call.parameters["page"]
        call.respond(FreeMarkerContent("page.ftl", mapOf(Pair("title", "Docs"), Pair("page", page))))
    }
}
