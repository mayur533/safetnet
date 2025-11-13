'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { authService } from '@/lib/services/auth';
import { useAuth } from '@/lib/contexts/auth-context';
import { toast } from 'sonner';
import { Security, Person, Lock, Error, Refresh, Login, VerifiedUser, Visibility, VisibilityOff } from '@mui/icons-material';

export default function LoginPage() {
  const router = useRouter();
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [errors, setErrors] = useState<{ username?: string; password?: string }>({});

  const validateForm = () => {
    const newErrors: { username?: string; password?: string } = {};

    if (!username) {
      newErrors.username = 'Username is required';
    }

    if (!password) {
      newErrors.password = 'Password is required';
    } else if (password.length < 6) {
      newErrors.password = 'Password must be at least 6 characters';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setIsLoading(true);

    try {
      const response = await authService.login({ username, password, rememberMe });
      login(response.user); // Update auth context
      toast.success('Login successful!');
      router.push('/');
    } catch (error: unknown) {
      console.error('Login error:', error);
      const errorMessage = (error as Error)?.message || 'Login failed. Please check your credentials.';
      toast.error(errorMessage);
      setErrors({ username: 'Invalid username or password' });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen relative overflow-hidden bg-gradient-to-br from-slate-900 via-indigo-950 to-slate-900 flex items-center justify-center p-4">
      {/* Animated Background Shapes */}
      <div className="absolute inset-0 overflow-hidden">
        {/* Gradient Orbs */}
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-indigo-500/20 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-blue-500/20 rounded-full blur-3xl animate-pulse delay-1000"></div>
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl"></div>
        
        {/* Geometric Shapes */}
        <div className="absolute top-20 right-20 w-32 h-32 border border-indigo-500/20 rounded-lg rotate-45 animate-spin-slow"></div>
        <div className="absolute bottom-40 left-40 w-24 h-24 border border-blue-500/20 rounded-full"></div>
        <div className="absolute top-1/3 right-1/3 w-16 h-16 bg-gradient-to-br from-indigo-500/10 to-blue-500/10 rounded-lg rotate-12"></div>
      </div>

      {/* Login Card */}
      <div className="relative z-10 w-full max-w-md">
        <div className="bg-card/40 backdrop-blur-2xl p-8 rounded-3xl shadow-2xl border border-border/50">
          {/* Logo */}
          <div className="flex flex-col items-center mb-8">
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-indigo-500 to-blue-600 flex items-center justify-center shadow-xl mb-4">
              <Security className="text-white w-10 h-10" />
            </div>
            <h1 className="text-2xl font-bold bg-gradient-to-r from-indigo-400 to-blue-400 bg-clip-text text-transparent">
              SafeTNet Admin
            </h1>
            <p className="text-sm text-white/80 mt-1">Security Management Portal</p>
          </div>

          {/* Login Form */}
          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Username */}
            <div className="space-y-2">
              <Label htmlFor="username" className="text-sm font-medium">
                Username
              </Label>
              <div className="relative">
                <Person className="absolute left-3 top-1/2 -translate-y-1/2 text-white/60 w-5 h-5" />
                <Input
                  id="username"
                  type="text"
                  placeholder="testadmin"
                  value={username}
                  onChange={(e) => {
                    setUsername(e.target.value);
                    if (errors.username) setErrors({ ...errors, username: undefined });
                  }}
                  className={`pl-10 bg-background/50 ${errors.username ? 'border-red-500' : ''}`}
                  disabled={isLoading}
                />
              </div>
            </div>

            {/* Password */}
            <div className="space-y-2">
              <Label htmlFor="password" className="text-sm font-medium">
                Password
              </Label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-white/60 w-5 h-5" />
                <Input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (errors.password) setErrors({ ...errors, password: undefined });
                  }}
                  className={`pl-10 pr-10 bg-background/50 ${errors.password ? 'border-red-500' : ''}`}
                  disabled={isLoading}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-white/60 hover:text-white/80 transition-colors"
                  disabled={isLoading}
                >
                  {showPassword ? (
                    <VisibilityOff className="w-5 h-5" />
                  ) : (
                    <Visibility className="w-5 h-5" />
                  )}
                </button>
              </div>
            </div>

            {/* Remember Me */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="remember"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="w-4 h-4 rounded border-border bg-background/50 text-indigo-600 focus:ring-2 focus:ring-indigo-500 focus:ring-offset-0"
                />
                <Label htmlFor="remember" className="text-sm cursor-pointer">
                  Remember me
                </Label>
              </div>
              <a
                href="/forgot-password"
                className="text-sm text-indigo-400 hover:text-indigo-300 transition-colors"
              >
                Forgot Password?
              </a>
            </div>

            {/* Error Summary - Shows all validation errors above button */}
            {(errors.username || errors.password) && (
              <div className="space-y-1">
                {errors.username && (
                  <p className="text-xs text-red-500 flex items-center gap-2">
                    <Error className="w-3 h-3" />
                    {errors.username}
                  </p>
                )}
                {errors.password && (
                  <p className="text-xs text-red-500 flex items-center gap-2">
                    <Error className="w-3 h-3" />
                    {errors.password}
                  </p>
                )}
              </div>
            )}

            {/* Login Button */}
            <Button
              type="submit"
              disabled={isLoading}
              className="w-full bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700 text-white py-6 text-base font-semibold shadow-xl hover:shadow-2xl transition-all duration-300"
            >
              {isLoading ? (
                <>
                  <Refresh className="animate-spin w-5 h-5 mr-2" />
                  Signing in...
                </>
              ) : (
                <>
                  <Login className="w-5 h-5 mr-2" />
                  Sign In
                </>
              )}
            </Button>
          </form>

          {/* Footer Links */}
          <div className="mt-6 pt-6 border-t border-border/50 text-center">
            <p className="text-xs text-white/70">
              Don&apos;t have an account?{' '}
              <a href="/register" className="text-indigo-400 hover:text-indigo-300 font-medium">
                Register
              </a>
            </p>
          </div>

          {/* Security Badge */}
          <div className="mt-6 flex items-center justify-center gap-2 text-xs text-white/70">
            <VerifiedUser className="w-4 h-4 text-green-500" />
            <span>Secured with end-to-end encryption</span>
          </div>
        </div>

        {/* Additional Info */}
        <div className="mt-6 text-center">
          <p className="text-xs text-white/60">
            © 2024 SafeTNet. All rights reserved.
          </p>
        </div>
      </div>

      {/* Custom CSS for slow spin animation */}
      <style jsx>{`
        @keyframes spin-slow {
          from {
            transform: rotate(0deg);
          }
          to {
            transform: rotate(360deg);
          }
        }
        .animate-spin-slow {
          animation: spin-slow 20s linear infinite;
        }
      `}</style>
    </div>
  );
}

