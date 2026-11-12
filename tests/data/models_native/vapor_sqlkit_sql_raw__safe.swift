// expect-none: DF004
import Vapor
import SQLKit

func routes(_ app: Application) throws {
    app.delete("notes", ":id") { req -> String in
        let id = req.parameters.get("id", as: Int.self)!
        let sqlDB = req.db as! SQLDatabase
        try await sqlDB.execute(sql: SQLRaw("DELETE FROM notes WHERE archived = 1")) { _ in }
        return "deleted \(id)"
    }
}
