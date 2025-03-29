import { NextResponse } from "next/server";
import jwt from "jsonwebtoken";
import { connectDB } from "@/lib/mongodb";
import User from "@/lib/models/user";

export async function authMiddleware(req) {
  await connectDB(); 

  const token = req.cookies.get("token")?.value || req.headers.get("Authorization")?.split(" ")[1];


  if (!token) {
    return NextResponse.json({ error: "Unauthorized. Token missing." }, { status: 401 });
  }

  try {
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    
    const user = await User.findById(decoded.id).select("-password");
    
    if (!user) {
      return NextResponse.json({ error: "User not found." }, { status: 404 });
    }

    
    return { user };
  } catch (error) {
    console.error("JWT Error:", error.message);
    return NextResponse.json({ error: "Invalid token." }, { status: 403 });
  }
}

