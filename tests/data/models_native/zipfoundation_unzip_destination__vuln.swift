// expect: DF005
import Vapor
import ZIPFoundation

func routes(_ app: Application) throws {
    app.post("bundles", ":slot") { req -> String in
        let slot = req.parameters.get("slot")!
        let archive = URL(fileURLWithPath: "/srv/incoming/bundle.zip")
        try FileManager.default.unzipItem(at: archive, to: URL(fileURLWithPath: "/srv/bundles/" + slot))
        return "unpacked"
    }
}
