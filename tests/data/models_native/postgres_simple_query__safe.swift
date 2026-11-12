// expect-none: DF004
import Vapor
import PostgresNIO

func routes(_ app: Application) throws {
    app.post("tenants", ":name") { req -> String in
        let name = req.parameters.get("name")!
        let conn = try await pool.connection()
        _ = try await conn.simpleQuery("CREATE SCHEMA IF NOT EXISTS tenants").get()
        return "created \(name.count)"
    }
}
