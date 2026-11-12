// expect-none: DF006
import Vapor

func routes(_ app: Application) throws {
    app.post("state") { req -> String in
        let blob = try req.content.decode(StateBlob.self)
        let state = try JSONDecoder().decode(SavedState.self, from: blob.payload)
        return "\(state.revision)"
    }
}
