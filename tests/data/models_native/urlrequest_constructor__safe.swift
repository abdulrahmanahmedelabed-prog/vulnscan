// expect-none: DF010
import Vapor

func routes(_ app: Application) throws {
    app.post("webhooks", "test") { req -> String in
        let hook = try req.content.decode(Hook.self)
        var outbound = URLRequest(url: URL(string: "https://hooks.example.com/ping")!)
        outbound.httpMethod = "POST"
        outbound.httpBody = hook.note.data(using: String.Encoding.utf8)
        let status = try await transport.perform(outbound)
        return "\(status)"
    }
}
