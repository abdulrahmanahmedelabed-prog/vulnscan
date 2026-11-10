// expect-none: DF012
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.queryParamOrNull
import javax.script.ScriptEngineManager

suspend fun calc(serverRequest: ServerRequest): Any? {
    val n = serverRequest.queryParamOrNull("n")?.toIntOrNull() ?: 0
    val engine = ScriptEngineManager().getEngineByName("js")
    return engine.eval("1 + " + n)
}
