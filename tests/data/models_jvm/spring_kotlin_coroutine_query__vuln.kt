// expect: DF012
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.queryParamOrNull
import javax.script.ScriptEngineManager

suspend fun calc(serverRequest: ServerRequest): Any? {
    val formula = serverRequest.queryParamOrNull("f")
    val engine = ScriptEngineManager().getEngineByName("js")
    return engine.eval(formula)
}
