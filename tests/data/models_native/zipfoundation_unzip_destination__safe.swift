// expect-none: DF005
import Vapor
import ZIPFoundation

func routes(_ app: Application) throws {
    app.post("bundles", ":slot") { req -> String in
        let slot = Int(req.parameters.get("slot")!) ?? 0
        let archive = URL(fileURLWithPath: "/srv/incoming/bundle.zip")
        try FileManager.default.unzipItem(at: archive, to: URL(fileURLWithPath: "/srv/bundles/slot-\(slot)"))
        return "unpacked"
    }
}
