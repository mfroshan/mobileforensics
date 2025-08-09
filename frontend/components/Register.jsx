"use client";
import { Eye, EyeOff, Mail, Lock, User, Sparkles } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

export default function Register() {
  const [hidePassword, setHidePassword] = useState(false);
  const [hideConfirmPassword, setHideConfirmPassword] = useState(false);
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    // password: "",
    // confirmPassword: ""
  });
  const router=useRouter()

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

   const handleSubmit = async (e) => {
    e.preventDefault();
  
   const res= await fetch("http://localhost:4000/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(formData)
    });
     if (res.ok) {
      router.push("/server");
    } else {
      console.log("data have not send to the server")
    }
    // Redirect or show message as needed
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-900 via-blue-900 to-indigo-900 flex items-center justify-center p-4 relative overflow-hidden">
      {/* Animated background elements */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -left-40 w-80 h-80 bg-blue-500 rounded-full mix-blend-multiply filter blur-xl opacity-70 animate-pulse"></div>
        <div className="absolute -bottom-40 -right-40 w-80 h-80 bg-pink-500 rounded-full mix-blend-multiply filter blur-xl opacity-70 animate-pulse delay-300"></div>
        <div className="absolute top-1/2 left-1/4 w-60 h-60 bg-purple-500 rounded-full mix-blend-multiply filter blur-xl opacity-70 animate-pulse delay-700"></div>
      </div>

      {/* Glassmorphism container */}
      <div className="relative w-full max-w-md">
        {/* Main form container */}
        <div className="backdrop-blur-xl bg-white/10 border border-white/20 rounded-3xl p-8 shadow-2xl relative overflow-hidden group hover:bg-white/15 transition-all duration-500">
          {/* Subtle inner glow */}
          <div className="absolute inset-0 bg-gradient-to-r from-white/5 to-transparent rounded-3xl pointer-events-none"></div>

          {/* Header with icon */}
          <div className="text-center mb-8 relative">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-r from-pink-500 to-purple-500 rounded-full mb-4 shadow-lg">
              <Sparkles className="w-8 h-8 text-white" />
            </div>
            <h1 className="text-3xl font-bold bg-gradient-to-r from-white to-purple-200 bg-clip-text text-transparent mb-2">
              Mobile forensics
            </h1>
            <p className="text-white/70 text-sm">Join our community today</p>
          </div>

          <div className="space-y-6">
            {/* Name field */}
            <div className="space-y-2">
              <label className="block text-white/90 text-sm font-medium">
                Full Name
              </label>
              <div className="relative group">
                <input
                  type="text"
                  name="name"
                  value={formData.name}
                  onChange={handleChange}
                  placeholder="Enter your full name"
                  className="w-full p-4 pl-12 pr-4 rounded-xl bg-white/10 border border-white/20 backdrop-blur-sm text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-pink-400 focus:border-transparent transition-all duration-300 hover:bg-white/15"
                />
                <User className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-white/60 group-focus-within:text-pink-400 transition-colors" />
              </div>
            </div>

            {/* Email field */}
            <div className="space-y-2">
              <label className="block text-white/90 text-sm font-medium">
                Email Address
              </label>
              <div className="relative group">
                <input
                  type="email"
                  name="email"
                  value={formData.email}
                  onChange={handleChange}
                  placeholder="Enter your email"
                  className="w-full p-4 pl-12 pr-4 rounded-xl bg-white/10 border border-white/20 backdrop-blur-sm text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-pink-400 focus:border-transparent transition-all duration-300 hover:bg-white/15"
                />
                <Mail className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-white/60 group-focus-within:text-pink-400 transition-colors" />
              </div>
            </div>

            {/* Password field */}
            {/* <div className="space-y-2">
              <label className="block text-white/90 text-sm font-medium">
                Password
              </label>
              <div className="relative group">
                <input
                  type={hidePassword ? "text" : "password"}
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
                  placeholder="Create a password"
                  className="w-full p-4 pl-12 pr-12 rounded-xl bg-white/10 border border-white/20 backdrop-blur-sm text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-pink-400 focus:border-transparent transition-all duration-300 hover:bg-white/15"
                />
                <Lock className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-white/60 group-focus-within:text-pink-400 transition-colors" />
                <button
                  type="button"
                  onClick={() => setHidePassword(!hidePassword)}
                  className="absolute right-4 top-1/2 transform -translate-y-1/2 text-white/60 hover:text-pink-400 transition-colors"
                >
                  {hidePassword ? (
                    <EyeOff className="w-5 h-5" />
                  ) : (
                    <Eye className="w-5 h-5" />
                  )}
                </button>
              </div>
            </div> */}

            {/* Confirm Password field */}
            {/* <div className="space-y-2">
              <label className="block text-white/90 text-sm font-medium">
                Confirm Password
              </label>
              <div className="relative group">
                <input
                  type={hideConfirmPassword ? "text" : "password"}
                  name="confirmPassword"
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  placeholder="Confirm your password"
                  className="w-full p-4 pl-12 pr-12 rounded-xl bg-white/10 border border-white/20 backdrop-blur-sm text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-pink-400 focus:border-transparent transition-all duration-300 hover:bg-white/15"
                />
                <Lock className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-white/60 group-focus-within:text-pink-400 transition-colors" />
                <button
                  type="button"
                  onClick={() => setHideConfirmPassword(!hideConfirmPassword)}
                  className="absolute right-4 top-1/2 transform -translate-y-1/2 text-white/60 hover:text-pink-400 transition-colors"
                >
                  {hideConfirmPassword ? (
                    <EyeOff className="w-5 h-5" />
                  ) : (
                    <Eye className="w-5 h-5" />
                  )}
                </button>
              </div>
            </div> */}

            {/* Terms checkbox */}
            <div className="flex items-start text-sm">
              <input
                type="checkbox"
                id="terms"
                className="mt-1 mr-2 rounded border-white/20 bg-white/10 text-pink-500 focus:ring-pink-400"
              />
              <label htmlFor="terms" className="text-white/70 hover:text-white transition-colors cursor-pointer">
                I agree to the <span className="text-pink-300 hover:text-pink-200">Terms of Service</span> and <span className="text-pink-300 hover:text-pink-200">Privacy Policy</span>
              </label>
            </div>

            {/* Register button */}
            <button
              type="submit"
              onClick={handleSubmit}
              className="w-full py-4 bg-gradient-to-r from-pink-500 to-purple-500 text-white font-semibold rounded-xl shadow-lg hover:from-pink-600 hover:to-purple-600 transform hover:scale-105 transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-pink-400 focus:ring-offset-2 focus:ring-offset-transparent"
            >
              Submit
            </button>

        
          </div>

          {/* Login link */}
        
        </div>
      </div>
    </div>
  );
}