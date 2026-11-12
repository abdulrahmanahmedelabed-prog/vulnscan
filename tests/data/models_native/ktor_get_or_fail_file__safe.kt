// expect-none: DF005
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.util.getOrFail
import java.io.File

fun Route.invoices() {
    get("/invoices/{name}") {
        val id = call.parameters.getOrFail("name").toLong()
        val text = File("/srv/invoices", "invoice-$id.txt").readText()
        call.respondText(text)
    }
}
