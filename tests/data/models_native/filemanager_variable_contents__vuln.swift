// expect: DF005
import Vapor

func routes(_ app: Application) throws {
    app.get("export", ":file") { req -> String in
        let file = req.parameters.get("file")!
        let fm = FileManager.default
        let data = fm.contents(atPath: "/srv/export/" + file) ?? Data()
        return "\(data.count)"
    }
}
