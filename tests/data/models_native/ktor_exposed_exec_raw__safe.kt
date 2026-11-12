// expect-none: DF004
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.jetbrains.exposed.sql.VarCharColumnType
import org.jetbrains.exposed.sql.transactions.TransactionManager

fun Route.tenantReport() {
    get("/report") {
        val tenant = call.request.header("X-Tenant") ?: "public"
        TransactionManager.current().exec(
            "UPDATE stats SET hits = hits + 1 WHERE tenant = ?",
            listOf(Pair(VarCharColumnType(), tenant))
        )
        call.respondText("ok")
    }
}
