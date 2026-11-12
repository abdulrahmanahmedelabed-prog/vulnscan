// expect: DF010
import Vapor

func routes(_ app: Application) throws {
    app.post("webhooks", "test") { req -> String in
        let hook = try req.content.decode(Hook.self)
        var outbound = URLRequest(url: URL(string: hook.endpoint)!)
        outbound.httpMethod = "POST"
        let status = try await transport.perform(outbound)
        return "\(status)"
    }
}
