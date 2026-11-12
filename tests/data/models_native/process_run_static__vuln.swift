// expect: DF002
import Vapor

func routes(_ app: Application) throws {
    app.post("thumbnails", ":name") { req -> String in
        let name = req.parameters.get("name")!
        try Process.run(URL(fileURLWithPath: "/bin/sh"), arguments: ["-c", "convert \(name) thumb.png"])
        return "queued"
    }
}
