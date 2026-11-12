// expect: DF010
import Vapor

func routes(_ app: Application) throws {
    app.get("preview") { req -> String in
        let target = try req.query.get(String.self, at: "url")
        let session = URLSession(configuration: URLSessionConfiguration.ephemeral)
        let (data, _) = try await session.data(from: URL(string: target)!)
        return "\(data.count)"
    }
}
