// expect: DF004
import Vapor
import SQLKit

func routes(_ app: Application) throws {
    app.delete("notes", ":id") { req -> String in
        let id = req.parameters.get("id")!
        let sqlDB = req.db as! SQLDatabase
        try await sqlDB.execute(sql: SQLRaw("DELETE FROM notes WHERE id = " + id)) { _ in }
        return "deleted"
    }
}
