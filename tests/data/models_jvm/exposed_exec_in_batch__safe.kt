// expect-none: DF004
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.routing.*
import org.jetbrains.exposed.sql.transactions.TransactionManager

fun Application.bulk() {
    routing {
        post("/bulk") {
            val body = call.receiveText()
            TransactionManager.current().execInBatch(listOf("DELETE FROM tmp", "VACUUM"))
        }
    }
}
