import  {NextResponse}  from "next/server";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import  {connectDB}  from "@/lib/mongodb";
import User from "@/lib/models/user";

export async function POST(req) {
  try {
    console.log("Starting API call");
    await connectDB();

    const { name, email, password, action } = await req.json();
    console.log("Received data:", { name, email, action });

    if (action === "signup") {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        console.error("User already exists");
        return NextResponse.json(
          { error: "User already exists" },
          { status: 400 }
        );
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      console.log("Password hashed");

      const newUser = await User.create({
        name,
        email,
        password: hashedPassword,
      });
      console.log("New user created:", newUser);

      return NextResponse.json(
        { message: "User registered successfully", userId: newUser._id },
        { status: 201 }
      );
    } else if (action === "login") {
      const user = await User.findOne({ email });
      if (!user) {
        console.error("User not found");
        return NextResponse.json(
          { error: "Invalid credentials" },
          { status: 401 }
        );
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        console.error("Password mismatch");
        return NextResponse.json(
          { error: "Invalid credentials" },
          { status: 401 }
        );
      }

      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
        expiresIn: "1d",
      });
      console.log("Token generated:", token);

      const response = NextResponse.json(
        { message: "Login successful", userId: user._id },
        { status: 200 }
      );

      response.cookies.set("token", token, {
        httpOnly: true,
        path: "/",
      });

      return response;
    }

    console.error("Invalid action");
    return NextResponse.json({ error: "Invalid action" }, { status: 400 });
  } catch (error) {
    console.error("❌ Auth Error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
