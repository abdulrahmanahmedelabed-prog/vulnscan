// expect: DF007
import Vapor
import Stencil

func routes(_ app: Application) throws {
    app.post("mail", "preview") { req -> String in
        let draft = try req.content.decode(Draft.self)
        let template = Template(templateString: draft.layout)
        let html = try template.render()
        return "\(html.count)"
    }
}
