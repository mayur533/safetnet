'use client';

import { useState, useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { authService } from '@/lib/services/auth';
import { toast } from 'sonner';
import { Security, VpnKey, Refresh, Error, Visibility, VisibilityOff, VerifiedUser } from '@mui/icons-material';

export default function ResetPasswordPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const email = searchParams.get('email');
  
  const [otp, setOtp] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [errors, setErrors] = useState<{ otp?: string; newPassword?: string; confirmPassword?: string }>({});
  const [passwordReset, setPasswordReset] = useState(false);

  useEffect(() => {
    if (!email) {
      router.push('/forgot-password');
    }
  }, [email, router]);

  const validateForm = () => {
    const newErrors: { otp?: string; newPassword?: string; confirmPassword?: string } = {};

    if (!otp) {
      newErrors.otp = 'OTP is required';
    } else if (otp.length !== 6) {
      newErrors.otp = 'OTP must be 6 digits';
    }

    if (!newPassword) {
      newErrors.newPassword = 'Password is required';
    } else if (newPassword.length < 8) {
      newErrors.newPassword = 'Password must be at least 8 characters';
    }

    if (!confirmPassword) {
      newErrors.confirmPassword = 'Please confirm password';
    } else if (newPassword !== confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
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
      await authService.resetPasswordWithOTP(email!, otp, newPassword);
      setPasswordReset(true);
      toast.success('Password reset successful!');
      setTimeout(() => {
        router.push('/login');
      }, 2000);
    } catch (error: unknown) {
      console.error('Password reset error:', error);
      const errorMessage = (error as Error)?.message || 'Password reset failed. Please try again.';
      toast.error(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  if (passwordReset) {
    return (
      <div className="min-h-screen relative overflow-hidden bg-gradient-to-br from-slate-900 via-indigo-950 to-slate-900 flex items-center justify-center p-4">
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute top-0 left-1/4 w-96 h-96 bg-indigo-500/20 rounded-full blur-3xl animate-pulse"></div>
          <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-blue-500/20 rounded-full blur-3xl animate-pulse delay-1000"></div>
        </div>

        <div className="relative z-10 w-full max-w-md">
          <div className="bg-card/40 backdrop-blur-2xl p-8 rounded-3xl shadow-2xl border border-border/50">
            <div className="flex flex-col items-center">
              <div className="w-20 h-20 rounded-full bg-green-500/20 flex items-center justify-center mb-4">
                <VerifiedUser className="text-green-400 w-10 h-10" />
              </div>
              <h2 className="text-2xl font-bold bg-gradient-to-r from-green-400 to-blue-400 bg-clip-text text-transparent mb-2">
                Password Reset Successful!
              </h2>
              <p className="text-sm text-white/70 text-center mb-6">
                Your password has been changed successfully.
              </p>
              <Link href="/login">
                <Button className="w-full bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700 text-white py-6 text-base font-semibold shadow-xl hover:shadow-2xl transition-all duration-300">
                  Continue to Login
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </div>
    );
  }

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

      {/* Reset Password Card */}
      <div className="relative z-10 w-full max-w-md">
        <div className="bg-card/40 backdrop-blur-2xl p-8 rounded-3xl shadow-2xl border border-border/50">
          {/* Logo */}
          <div className="flex flex-col items-center mb-8">
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-indigo-500 to-blue-600 flex items-center justify-center shadow-xl mb-4">
              <VpnKey className="text-white w-10 h-10" />
            </div>
            <h1 className="text-2xl font-bold bg-gradient-to-r from-indigo-400 to-blue-400 bg-clip-text text-transparent">
              Reset Password
            </h1>
            <p className="text-sm text-white/80 mt-1">Enter OTP and new password</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Email Display */}
            <div className="bg-indigo-500/10 border border-indigo-500/30 rounded-lg p-3 text-center">
              <p className="text-xs text-white/60">Verifying</p>
              <p className="text-sm font-medium text-white">{email}</p>
            </div>

            {/* OTP */}
            <div className="space-y-2">
              <Label htmlFor="otp" className="text-sm font-medium">
                OTP Code
              </Label>
              <div className="relative">
                <VpnKey className="absolute left-3 top-1/2 -translate-y-1/2 text-white/60 w-5 h-5" />
                <Input
                  id="otp"
                  type="text"
                  placeholder="000000"
                  value={otp}
                  onChange={(e) => {
                    const value = e.target.value.replace(/\D/g, '').slice(0, 6);
                    setOtp(value);
                    if (errors.otp) setErrors({ ...errors, otp: undefined });
                  }}
                  className={`pl-10 bg-background/50 text-center text-2xl tracking-widest ${errors.otp ? 'border-red-500' : ''}`}
                  disabled={isLoading}
                />
              </div>
              {errors.otp && (
                <p className="text-xs text-red-500 flex items-center gap-2">
                  <Error className="w-3 h-3" />
                  {errors.otp}
                </p>
              )}
            </div>

            {/* New Password */}
            <div className="space-y-2">
              <Label htmlFor="newPassword" className="text-sm font-medium">
                New Password
              </Label>
              <div className="relative">
                <Security className="absolute left-3 top-1/2 -translate-y-1/2 text-white/60 w-5 h-5" />
                <Input
                  id="newPassword"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Enter new password"
                  value={newPassword}
                  onChange={(e) => {
                    setNewPassword(e.target.value);
                    if (errors.newPassword) setErrors({ ...errors, newPassword: undefined });
                  }}
                  className={`pl-10 pr-10 bg-background/50 ${errors.newPassword ? 'border-red-500' : ''}`}
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
              {errors.newPassword && (
                <p className="text-xs text-red-500 flex items-center gap-2">
                  <Error className="w-3 h-3" />
                  {errors.newPassword}
                </p>
              )}
            </div>

            {/* Confirm Password */}
            <div className="space-y-2">
              <Label htmlFor="confirmPassword" className="text-sm font-medium">
                Confirm Password
              </Label>
              <div className="relative">
                <Security className="absolute left-3 top-1/2 -translate-y-1/2 text-white/60 w-5 h-5" />
                <Input
                  id="confirmPassword"
                  type={showConfirmPassword ? 'text' : 'password'}
                  placeholder="Confirm new password"
                  value={confirmPassword}
                  onChange={(e) => {
                    setConfirmPassword(e.target.value);
                    if (errors.confirmPassword) setErrors({ ...errors, confirmPassword: undefined });
                  }}
                  className={`pl-10 pr-10 bg-background/50 ${errors.confirmPassword ? 'border-red-500' : ''}`}
                  disabled={isLoading}
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-white/60 hover:text-white/80 transition-colors"
                  disabled={isLoading}
                >
                  {showConfirmPassword ? (
                    <VisibilityOff className="w-5 h-5" />
                  ) : (
                    <Visibility className="w-5 h-5" />
                  )}
                </button>
              </div>
              {errors.confirmPassword && (
                <p className="text-xs text-red-500 flex items-center gap-2">
                  <Error className="w-3 h-3" />
                  {errors.confirmPassword}
                </p>
              )}
            </div>

            {/* Reset Button */}
            <Button
              type="submit"
              disabled={isLoading}
              className="w-full bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700 text-white py-6 text-base font-semibold shadow-xl hover:shadow-2xl transition-all duration-300"
            >
              {isLoading ? (
                <>
                  <Refresh className="animate-spin w-5 h-5 mr-2" />
                  Resetting...
                </>
              ) : (
                <>
                  <VpnKey className="w-5 h-5 mr-2" />
                  Reset Password
                </>
              )}
            </Button>
          </form>

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

