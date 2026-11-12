// expect-none: DF002
import Vapor

func routes(_ app: Application) throws {
    app.post("thumbnails", ":name") { req -> String in
        let name = req.parameters.get("name")!
        try Process.run(URL(fileURLWithPath: "/usr/bin/uptime"), arguments: [])
        return "queued \(name.count)"
    }
}
