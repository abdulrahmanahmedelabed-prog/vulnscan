// expect-none: DF010
import AsyncHTTPClient
import Foundation

// a constant URL held in a variable named `url` is not a deep link
func fetchStatus(client: HTTPClient) async throws {
    let url = URL(string: "https://status.example.com/api")!
    let request = HTTPClientRequest(url: url.absoluteString)
    let response = try await client.execute(request)
}
