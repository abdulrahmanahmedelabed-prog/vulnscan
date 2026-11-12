// expect-none: DF015
import Vapor
import Kanna

func routes(_ app: Application) throws {
    app.get("feeds") { req -> String in
        let tag = try req.query.get(String.self, at: "tag")
        let doc = try Kanna.XML(xml: feedXML, encoding: String.Encoding.utf8)
        let items = doc.xpath("//item[category='news']")
        return "\(items.count + tag.count)"
    }
}
