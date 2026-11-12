// expect: DF012
import Vapor

func routes(_ app: Application) throws {
    app.get("calc") { req -> String in
        let formula = try req.query.get(String.self, at: "formula")
        let expression = NSExpression(format: formula)
        let value = expression.expressionValue(with: nil, context: nil) as? NSNumber
        return "\(value ?? 0)"
    }
}
