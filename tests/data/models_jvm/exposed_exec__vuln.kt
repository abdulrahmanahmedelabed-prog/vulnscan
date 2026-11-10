// expect: DF004
import io.ktor.server.application.*
import io.ktor.server.routing.*
import org.jetbrains.exposed.sql.transactions.TransactionManager
import org.jetbrains.exposed.sql.transactions.transaction

fun Application.report() {
    routing {
        get("/report") {
            transaction {
                val region = call.request.queryParameters["region"]
                TransactionManager.current().exec("SELECT * FROM sales WHERE region = '" + region + "'")
            }
        }
    }
}
