// expect-none: DF005
import Vapor

func routes(_ app: Application) throws {
    app.post("avatars") { req -> String in
        let upload = try req.content.decode(Avatar.self)
        let target = "/var/avatars/" + UUID().uuidString + ".png"
        try await req.fileio.writeFile(upload.image, at: target)
        return "stored"
    }
}
