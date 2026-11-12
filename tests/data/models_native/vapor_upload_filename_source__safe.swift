// expect-none: DF005
import Vapor

struct UploadController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        routes.post("documents", use: store)
    }

    func store(req: Request) throws -> String {
        let created = FileManager.default.createFile(atPath: "/srv/documents/" + UUID().uuidString, contents: nil)
        return created ? "ok" : "failed"
    }
}
