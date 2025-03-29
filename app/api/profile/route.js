import { authMiddleware } from "@/lib/middleware/authMiddleware";
import { NextResponse } from "next/server";
export async function GET(req) {
  const auth = await authMiddleware(req);
  
  
  if (auth.error) return auth;

  
  return NextResponse.json({ user: auth.user });
}
