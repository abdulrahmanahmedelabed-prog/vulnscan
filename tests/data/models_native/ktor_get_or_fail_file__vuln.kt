// expect: DF005
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.util.getOrFail
import java.io.File

fun Route.invoices() {
    get("/invoices/{name}") {
        val name = call.parameters.getOrFail("name")
        val text = File("/srv/invoices", name).readText()
        call.respondText(text)
    }
}
