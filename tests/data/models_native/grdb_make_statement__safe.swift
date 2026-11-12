// expect-none: DF004
import GRDB
import Vapor

struct ScoreController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        routes.get("scores", use: index)
    }

    func index(req: Request) throws -> String {
        let column = try req.query.get(String.self, at: "sort")
        let database = try pool.makeDatabase()
        let statement = try database.makeStatement(sql: "SELECT score FROM player ORDER BY score")
        let total = try Int.fetchOne(statement) ?? 0
        return "\(total) \(column.count)"
    }
}
