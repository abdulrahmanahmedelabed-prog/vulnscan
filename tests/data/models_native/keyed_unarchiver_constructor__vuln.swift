// expect: DF006
import Vapor

func routes(_ app: Application) throws {
    app.post("state") { req -> String in
        let blob = try req.content.decode(StateBlob.self)
        let unarchiver = NSKeyedUnarchiver(forReadingWith: blob.payload)
        let state = unarchiver.decodeObject(forKey: "root") as? SavedState
        return state?.title ?? ""
    }
}
