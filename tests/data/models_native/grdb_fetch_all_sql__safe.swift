// expect-none: DF004
import GRDB
import Vapor

struct PlayerController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        routes.get("players", use: index)
    }

    func index(req: Request) throws -> String {
        let team = try req.query.get(String.self, at: "team")
        let db = try pool.makeDatabase()
        let rows = try Row.fetchAll(db, sql: "SELECT * FROM player WHERE team = ?", arguments: [team])
        return "\(rows.count)"
    }
}
