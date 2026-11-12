// expect-none: DF010
import Vapor
import AsyncHTTPClient

func routes(_ app: Application) throws {
    app.get("mirror") { req -> String in
        let source = try req.query.get(String.self, at: "source")
        let outbound = HTTPClientRequest(url: "https://mirror.example.com/index.json")
        let response = try await HTTPClient.shared.execute(outbound, timeout: TimeAmount.seconds(10))
        return "\(response.status.code) \(source.count)"
    }
}
