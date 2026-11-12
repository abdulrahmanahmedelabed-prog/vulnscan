// expect: DF015
import Vapor

func routes(_ app: Application) throws {
    app.get("catalog") { req -> String in
        let author = try req.query.get(String.self, at: "author")
        let document = try XMLDocument(contentsOf: catalogURL, options: [])
        let books = try document.nodes(forXPath: "//book[author='" + author + "']/title")
        return "\(books.count)"
    }
}
