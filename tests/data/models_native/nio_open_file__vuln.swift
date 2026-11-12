// expect: DF005
import Vapor
import NIO

func routes(_ app: Application) throws {
    app.get("media", ":clip") { req -> String in
        let clip = req.parameters.get("clip")!
        let handle = try await fileIO.openFile(path: "/srv/media/" + clip, eventLoop: req.eventLoop).get()
        try handle.0.close()
        return "ok"
    }
}
