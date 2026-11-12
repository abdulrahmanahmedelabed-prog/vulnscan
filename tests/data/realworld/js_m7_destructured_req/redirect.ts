import { type Request, type Response, type NextFunction } from 'express'
import express from 'express'
const app = express()

// MISS: destructured request parameter in a handler returned by a factory (Juice Shop routes/redirect.ts style)
export function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const toUrl: string = query.to as string
    res.redirect(toUrl)
  }
}
app.get('/redirect', performRedirect())

// direct registration with destructuring
app.get('/r2', ({ query }: Request, res: Response) => { res.redirect(query.to as string) })

// safe twin: constant target
app.get('/r3', ({ query }: Request, res: Response) => { res.redirect('/home') })

// contrast (reported today): non-destructured
export function performRedirect2 () {
  return (req: Request, res: Response) => { res.redirect(req.query.to as string) }
}
app.get('/redirect2', performRedirect2())
