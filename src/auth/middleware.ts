import type { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";

declare module "express-serve-static-core" {
  interface Request {
    userId?: string;
  }
}

export function requireAuth(jwtSecret: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const header = req.headers.authorization;
    const token = header?.startsWith("Bearer ") ? header.slice(7) : undefined;
    if (!token) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }
    try {
      const payload = jwt.verify(token, jwtSecret, { algorithms: ["HS256"] });
      if (typeof payload === "string" || typeof payload.sub !== "string") {
        throw new Error("Invalid subject");
      }
      req.userId = payload.sub;
      next();
    } catch {
      res.status(401).json({ error: "Invalid or expired token" });
    }
  };
}
