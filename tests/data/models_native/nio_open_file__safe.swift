// expect-none: DF005
import Vapor
import NIO

func routes(_ app: Application) throws {
    app.get("media", ":clip") { req -> String in
        let clip = Int(req.parameters.get("clip")!) ?? 0
        let handle = try await fileIO.openFile(path: "/srv/media/\(clip).mp4", eventLoop: req.eventLoop).get()
        try handle.0.close()
        return "ok"
    }
}
