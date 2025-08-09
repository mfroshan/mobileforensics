"use client";
import { Eye, EyeOff, Mail, Lock, Sparkles } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

export default function Login() {
  const [hide, setHide] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-900 via-blue-900 to-indigo-900 flex items-center justify-center p-4 relative overflow-hidden">
      {/* Animated background elements - Removed pointer-events-none from parent div */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-purple-500 rounded-full mix-blend-multiply filter blur-xl opacity-70 animate-pulse pointer-events-none"></div>
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-purple-500 rounded-full mix-blend-multiply filter blur-xl opacity-70 animate-pulse pointer-events-none"></div>
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-purple-500 rounded-full mix-blend-multiply filter blur-xl opacity-70 animate-pulse pointer-events-none"></div>
      </div>

      {/* Glassmorphism container */}
      <div className="relative w-full max-w-md">
        {/* Main form container */}
        <div className="backdrop-blur-xl bg-white/10 border border-white/20 rounded-3xl p-8 shadow-2xl relative overflow-hidden group hover:bg-white/15 transition-all duration-500">
          {/* Subtle inner glow */}
          <div className="absolute inset-0 bg-gradient-to-r from-white/5 to-transparent rounded-3xl pointer-events-none"></div>

          {/* Header with icon */}
          <div className="text-center mb-8 relative">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-r from-purple-500 to-pink-500 rounded-full mb-4 shadow-lg">
              <Sparkles className="w-8 h-8 text-white" />
            </div>
            <h1 className="text-3xl font-bold bg-gradient-to-r from-white to-purple-200 bg-clip-text text-transparent mb-2">
              Welcome Back
            </h1>
            <p className="text-white/70 text-sm">Sign in to your account</p>
          </div>

          <div className="space-y-6">
            {/* Email field */}
            <div className="space-y-2">
              <label className="block text-white/90 text-sm font-medium">
                Email Address
              </label>
              <div className="relative group">
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Enter your email"
                  className="w-full p-4 pl-12 pr-4 rounded-xl bg-white/10 border border-white/20 backdrop-blur-sm text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-purple-400 focus:border-transparent transition-all duration-300 hover:bg-white/15"
                />
                <Mail className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-white/60 group-focus-within:text-purple-400 transition-colors" />
              </div>
            </div>

            {/* Password field */}
            <div className="space-y-2">
              <label className="block text-white/90 text-sm font-medium">
                Password
              </label>
              <div className="relative group">
                <input
                  type={hide ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  className="w-full p-4 pl-12 pr-12 rounded-xl bg-white/10 border border-white/20 backdrop-blur-sm text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-purple-400 focus:border-transparent transition-all duration-300 hover:bg-white/15"
                />
                <Lock className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-white/60 group-focus-within:text-purple-400 transition-colors" />
                <button
                  type="button"
                  onClick={() => setHide(!hide)}
                  className="absolute right-4 top-1/2 transform -translate-y-1/2 text-white/60 hover:text-purple-400 transition-colors"
                >
                  {hide ? (
                    <EyeOff className="w-5 h-5" />
                  ) : (
                    <Eye className="w-5 h-5" />
                  )}
                </button>
              </div>
            </div>

            {/* Remember me & Forgot password */}
            <div className="flex items-center justify-between text-sm">
              <label className="flex items-center text-white/70 cursor-pointer hover:text-white transition-colors">
                <input
                  type="checkbox"
                  className="mr-2 rounded border-white/20 bg-white/10 text-purple-500 focus:ring-purple-400"
                />
                Remember me
              </label>
              <Link
                href="/forgot-password"
                className="text-purple-300 hover:text-purple-200 transition-colors"
              >
                Forgot password?
              </Link>
            </div>

            {/* Login button */}
            <button
              type="submit"
              className="w-full py-4 bg-gradient-to-r from-purple-500 to-pink-500 text-white font-semibold rounded-xl shadow-lg hover:from-purple-600 hover:to-pink-600 transform hover:scale-105 transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-purple-400 focus:ring-offset-2 focus:ring-offset-transparent"
            >
              Sign In
            </button>

            {/* Divider */}
            <div className="relative my-6">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-white/20"></div>
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-4 bg-gradient-to-r from-purple-900 to-blue-900 text-white/70">
                  Or continue with
                </span>
              </div>
            </div>
          </div>

          {/* Register link */}
          <div className="mt-8 text-center">
            <p className="text-white/70 text-sm">
              Don't have an account?{" "}
              <Link
                href="/register"
                className="text-purple-300 hover:text-purple-200 font-medium transition-colors hover:underline cursor-pointer"
              >
                Create one now
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}