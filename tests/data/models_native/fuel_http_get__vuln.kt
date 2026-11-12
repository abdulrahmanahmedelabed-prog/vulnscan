// expect: DF010
import com.github.kittinunf.fuel.httpGet
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Route.preview() {
    get("/preview") {
        val target = call.request.queryParameters["url"] ?: return@get
        val (_, _, result) = target.httpGet().responseString()
        call.respondText(result.get())
    }
}
