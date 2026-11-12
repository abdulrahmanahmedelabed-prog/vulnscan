// expect-none: DF007
import Vapor
import Stencil

func routes(_ app: Application) throws {
    app.post("mail", "preview") { req -> String in
        let draft = try req.content.decode(Draft.self)
        let template = Template(templateString: "Hello {{ name }}")
        var context = Dictionary<String, Any>()
        context["name"] = draft.name
        let html = try template.render(context)
        return "\(html.count)"
    }
}
