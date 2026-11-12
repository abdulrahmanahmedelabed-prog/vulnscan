// expect-none: DF004
import SQLite
import Vapor

func routes(_ app: Application, db: Connection) throws {
    app.delete("users") { req -> String in
        let name = try req.query.get(String.self, at: "name")
        try db.run("DELETE FROM users WHERE name = ?", name)
        return "deleted"
    }
}
