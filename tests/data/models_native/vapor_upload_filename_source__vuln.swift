// expect: DF005
import Vapor

struct UploadController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        routes.post("documents", use: store)
    }

    func store(req: Request) throws -> String {
        let form = try req.content.decode(DocumentForm.self)
        let file = form.document
        let created = FileManager.default.createFile(atPath: "/srv/documents/" + file.filename, contents: nil)
        return created ? "ok" : "failed"
    }
}
