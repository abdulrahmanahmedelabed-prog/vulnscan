// expect-none: DF004
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotliquery.queryOf
import kotliquery.sessionOf
import javax.sql.DataSource

fun Route.orders(ds: DataSource) {
    get("/orders") {
        val status = call.request.queryParameters["status"]
        val session = sessionOf(ds)
        val query = queryOf("SELECT id FROM orders WHERE status = ?", status)
        val count = session.run(query.map { row -> row.long("id") }.asList).size
        session.close()
        call.respondText("orders: $count")
    }
}
