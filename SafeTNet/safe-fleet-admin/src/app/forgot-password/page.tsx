'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { authService } from '@/lib/services/auth';
import { toast } from 'sonner';
import { Email, Refresh, Error, VpnKey } from '@mui/icons-material';

export default function ForgotPasswordPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [emailSent, setEmailSent] = useState(false);
  const [errors, setErrors] = useState<{ email?: string }>({});

  const validateForm = () => {
    const newErrors: { email?: string } = {};

    if (!email) {
      newErrors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      newErrors.email = 'Invalid email format';
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
      await authService.requestPasswordReset(email);
      setEmailSent(true);
      toast.success('OTP sent to your email!');
    } catch (error: unknown) {
      console.error('Password reset request error:', error);
      const errorMessage = (error as Error)?.message || 'Failed to send OTP. Please try again.';
      toast.error(errorMessage);
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

      {/* Forgot Password Card */}
      <div className="relative z-10 w-full max-w-md">
        <div className="bg-card/40 backdrop-blur-2xl p-8 rounded-3xl shadow-2xl border border-border/50">
          {/* Logo */}
          <div className="flex flex-col items-center mb-8">
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-indigo-500 to-blue-600 flex items-center justify-center shadow-xl mb-4">
              <VpnKey className="text-white w-10 h-10" />
            </div>
            <h1 className="text-2xl font-bold bg-gradient-to-r from-indigo-400 to-blue-400 bg-clip-text text-transparent">
              Forgot Password
            </h1>
            <p className="text-sm text-white/80 mt-1">Enter your email to receive OTP</p>
          </div>

          {!emailSent ? (
            <form onSubmit={handleSubmit} className="space-y-5">
              {/* Email */}
              <div className="space-y-2">
                <Label htmlFor="email" className="text-sm font-medium">
                  Email Address
                </Label>
                <div className="relative">
                  <Email className="absolute left-3 top-1/2 -translate-y-1/2 text-white/60 w-5 h-5" />
                  <Input
                    id="email"
                    type="email"
                    placeholder="your.email@example.com"
                    value={email}
                    onChange={(e) => {
                      setEmail(e.target.value);
                      if (errors.email) setErrors({ email: undefined });
                    }}
                    className={`pl-10 bg-background/50 ${errors.email ? 'border-red-500' : ''}`}
                    disabled={isLoading}
                  />
                </div>
                {errors.email && (
                  <p className="text-xs text-red-500 flex items-center gap-2">
                    <Error className="w-3 h-3" />
                    {errors.email}
                  </p>
                )}
              </div>

              {/* Submit Button */}
              <Button
                type="submit"
                disabled={isLoading}
                className="w-full bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700 text-white py-6 text-base font-semibold shadow-xl hover:shadow-2xl transition-all duration-300"
              >
                {isLoading ? (
                  <>
                    <Refresh className="animate-spin w-5 h-5 mr-2" />
                    Sending OTP...
                  </>
                ) : (
                  <>
                    <Email className="w-5 h-5 mr-2" />
                    Send OTP
                  </>
                )}
              </Button>
            </form>
          ) : (
            <div className="space-y-5">
              {/* Success Message */}
              <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4 text-center">
                <div className="flex flex-col items-center">
                  <div className="w-16 h-16 rounded-full bg-green-500/20 flex items-center justify-center mb-3">
                    <Email className="text-green-400 w-8 h-8" />
                  </div>
                  <p className="text-sm text-white/90 font-medium">
                    OTP Sent Successfully!
                  </p>
                  <p className="text-xs text-white/70 mt-2">
                    Check your email for the verification code
                  </p>
                </div>
              </div>

              {/* Continue Button */}
              <Button
                onClick={() => router.push(`/reset-password?email=${encodeURIComponent(email)}`)}
                className="w-full bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700 text-white py-6 text-base font-semibold shadow-xl hover:shadow-2xl transition-all duration-300"
              >
                Continue to Reset Password
              </Button>

              {/* Resend OTP */}
              <Button
                onClick={async () => {
                  setEmailSent(false);
                  setIsLoading(true);
                  try {
                    await authService.requestPasswordReset(email);
                    setEmailSent(true);
                    toast.success('OTP resent successfully!');
                  } catch (error: unknown) {
                    console.error('Resend OTP error:', error);
                    const errorMessage = (error as Error)?.message || 'Failed to resend OTP. Please try again.';
                    toast.error(errorMessage);
                  } finally {
                    setIsLoading(false);
                  }
                }}
                variant="outline"
                className="w-full border-indigo-500/30 text-indigo-400 hover:bg-indigo-500/10"
              >
                Resend OTP
              </Button>
            </div>
          )}

          {/* Back to Login */}
          <div className="mt-6 pt-6 border-t border-border/50 text-center">
            <Link
              href="/login"
              className="text-sm text-indigo-400 hover:text-indigo-300 transition-colors"
            >
              ← Back to Login
            </Link>
          </div>
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

