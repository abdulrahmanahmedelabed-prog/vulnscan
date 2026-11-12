// expect-none: DF012
import Vapor

func routes(_ app: Application) throws {
    app.get("calc") { req -> String in
        let amount = try req.query.get(Double.self, at: "amount")
        let expression = NSExpression(format: "%@ * 1.15", NSNumber(value: amount))
        let value = expression.expressionValue(with: nil, context: nil) as? NSNumber
        return "\(value ?? 0)"
    }
}
