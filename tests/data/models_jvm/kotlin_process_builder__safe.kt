// expect-none: DF003 DF002 DF009
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.routing.*

fun Application.convert() {
    routing {
        post("/convert") {
            val opts = call.receiveText()
            ProcessBuilder("convert", "-version").start().waitFor()
        }
    }
}
