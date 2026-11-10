// expect: DF003
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.routing.*

fun Application.convert() {
    routing {
        post("/convert") {
            val opts = call.receiveText()
            ProcessBuilder("sh", "-c", "convert " + opts).start().waitFor()
        }
    }
}
