'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { authService } from '@/lib/services/auth';
import { convertRoleToAPI } from '@/lib/utils/role-converter';
import { toast } from 'sonner';

const roles = ['Admin', 'Sub-Admin'];

const geofences = [
  'Downtown Area',
  'University Campus',
  'Shopping Mall',
  'Business District',
  'Residential Zone A',
  'Industrial Park',
  'Medical District',
  'Entertainment Zone',
];

export default function RegisterPage() {
  const router = useRouter();
  const [formData, setFormData] = useState({
    username: '',
    fullName: '',
    email: '',
    password: '',
    confirmPassword: '',
    role: '',
    assignedGeofence: '',
  });
  const [isLoading, setIsLoading] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const handleChange = (field: string, value: string) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
    if (errors[field]) {
      setErrors((prev) => ({ ...prev, [field]: '' }));
    }
  };

  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    if (!formData.username.trim()) {
      newErrors.username = 'Username is required';
    }

    if (!formData.fullName.trim()) {
      newErrors.fullName = 'Full name is required';
    }

    if (!formData.email) {
      newErrors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = 'Invalid email format';
    }

    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (formData.password.length < 8) {
      newErrors.password = 'Password must be at least 8 characters';
    }

    if (!formData.confirmPassword) {
      newErrors.confirmPassword = 'Please confirm password';
    } else if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
    }

    if (!formData.role) {
      newErrors.role = 'Please select a role';
    }

    if (formData.role === 'Sub-Admin' && !formData.assignedGeofence) {
      newErrors.assignedGeofence = 'Please select a geofence for Sub-Admin';
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
      await authService.register({
        username: formData.username,
        email: formData.email,
        password: formData.password,
        password_confirm: formData.confirmPassword,
        full_name: formData.fullName,
        role: convertRoleToAPI(formData.role),
      });
      toast.success('Registration successful! Please login with your credentials.');
      router.push('/login');
    } catch (error: unknown) {
      console.error('Registration error:', error);
      try {
        const errorMessage = error instanceof Error ? error.message : 'Registration failed';
        const errorObj = JSON.parse(errorMessage);
        const errorMessages = Object.entries(errorObj)
          .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : value}`)
          .join('\n');
        toast.error(errorMessages || 'Registration failed');
        setErrors(errorObj);
      } catch {
        toast.error(error instanceof Error ? error.message : 'Registration failed');
      }
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

      {/* Registration Card */}
      <div className="relative z-10 w-full max-w-lg">
        <div className="bg-card/40 backdrop-blur-2xl p-8 rounded-3xl shadow-2xl border border-border/50">
          {/* Logo */}
          <div className="flex flex-col items-center mb-8">
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-indigo-500 to-blue-600 flex items-center justify-center shadow-xl mb-4">
              <span className="material-icons text-white" style={{ fontSize: '40px' }}>
                security
              </span>
            </div>
            <h1 className="text-2xl font-bold bg-gradient-to-r from-indigo-400 to-blue-400 bg-clip-text text-transparent">
              Create Account
            </h1>
            <p className="text-sm text-white/80 mt-1">Register for SafeTNet Admin</p>
          </div>

          {/* Registration Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Username */}
            <div className="space-y-2">
              <Label htmlFor="username" className="text-sm font-medium">
                Username
              </Label>
              <div className="relative">
                <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-white/60 text-lg">
                  account_circle
                </span>
                <Input
                  id="username"
                  type="text"
                  placeholder="Enter username"
                  value={formData.username}
                  onChange={(e) => handleChange('username', e.target.value)}
                  className={`pl-10 bg-background/50 ${errors.username ? 'border-red-500' : ''}`}
                  disabled={isLoading}
                />
              </div>
            </div>

            {/* Full Name */}
            <div className="space-y-2">
              <Label htmlFor="fullName" className="text-sm font-medium">
                Full Name
              </Label>
              <div className="relative">
                <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-white/60 text-lg">
                  person
                </span>
                <Input
                  id="fullName"
                  type="text"
                  placeholder="Enter your full name"
                  value={formData.fullName}
                  onChange={(e) => handleChange('fullName', e.target.value)}
                  className={`pl-10 bg-background/50 ${errors.fullName ? 'border-red-500' : ''}`}
                  disabled={isLoading}
                />
              </div>
            </div>

            {/* Email */}
            <div className="space-y-2">
              <Label htmlFor="email" className="text-sm font-medium">
                Email Address
              </Label>
              <div className="relative">
                <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-white/60 text-lg">
                  email
                </span>
                <Input
                  id="email"
                  type="email"
                  placeholder="admin@safefleet.com"
                  value={formData.email}
                  onChange={(e) => handleChange('email', e.target.value)}
                  className={`pl-10 bg-background/50 ${errors.email ? 'border-red-500' : ''}`}
                />
              </div>
            </div>

            {/* Password Fields */}
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label htmlFor="password" className="text-sm font-medium">
                  Password
                </Label>
                <div className="relative">
                  <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-white/60 text-lg">
                    lock
                  </span>
                  <Input
                    id="password"
                    type="password"
                    placeholder="Min. 8 chars"
                    value={formData.password}
                    onChange={(e) => handleChange('password', e.target.value)}
                    className={`pl-10 bg-background/50 ${errors.password ? 'border-red-500' : ''}`}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="confirmPassword" className="text-sm font-medium">
                  Confirm
                </Label>
                <div className="relative">
                  <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-white/60 text-lg">
                    lock_outline
                  </span>
                  <Input
                    id="confirmPassword"
                    type="password"
                    placeholder="Re-enter"
                    value={formData.confirmPassword}
                    onChange={(e) => handleChange('confirmPassword', e.target.value)}
                    className={`pl-10 bg-background/50 ${errors.confirmPassword ? 'border-red-500' : ''}`}
                  />
                </div>
              </div>
            </div>

            {/* Role */}
            <div className="space-y-2">
              <Label htmlFor="role" className="text-sm font-medium">
                Role
              </Label>
              <div className="relative">
                <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-white/60 text-lg z-10">
                  admin_panel_settings
                </span>
                <Select value={formData.role} onValueChange={(value) => handleChange('role', value)}>
                  <SelectTrigger className={`pl-10 bg-background/50 ${errors.role ? 'border-red-500' : ''}`}>
                    <SelectValue placeholder="Select your role" />
                  </SelectTrigger>
                  <SelectContent>
                    {roles.map((role) => (
                      <SelectItem key={role} value={role}>
                        {role}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Assigned Geofence - Only for Sub-Admin */}
            {formData.role === 'Sub-Admin' && (
              <div className="space-y-2">
                <Label htmlFor="assignedGeofence" className="text-sm font-medium">
                  Assigned Geofence
                </Label>
                <div className="relative">
                  <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-white/60 text-lg z-10">
                    location_on
                  </span>
                  <Select
                    value={formData.assignedGeofence}
                    onValueChange={(value) => handleChange('assignedGeofence', value)}
                  >
                    <SelectTrigger className={`pl-10 bg-background/50 ${errors.assignedGeofence ? 'border-red-500' : ''}`}>
                      <SelectValue placeholder="Select geofence" />
                    </SelectTrigger>
                    <SelectContent>
                      {geofences.map((geofence) => (
                        <SelectItem key={geofence} value={geofence}>
                          {geofence}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
            )}

            {/* Error Summary - Shows all validation errors above button */}
            {(errors.username || errors.fullName || errors.email || errors.password || errors.confirmPassword || errors.role || errors.assignedGeofence) && (
              <div className="space-y-1">
                {errors.username && (
                  <p className="text-xs text-red-500 flex items-center gap-2">
                    <span className="material-icons text-xs">error</span>
                    {errors.username}
                  </p>
                )}
                {errors.fullName && (
                  <p className="text-xs text-red-500 flex items-center gap-2">
                    <span className="material-icons text-xs">error</span>
                    {errors.fullName}
                  </p>
                )}
                {errors.email && (
                  <p className="text-xs text-red-500 flex items-center gap-2">
                    <span className="material-icons text-xs">error</span>
                    {errors.email}
                  </p>
                )}
                {errors.password && (
                  <p className="text-xs text-red-500 flex items-center gap-2">
                    <span className="material-icons text-xs">error</span>
                    {errors.password}
                  </p>
                )}
                {errors.confirmPassword && (
                  <p className="text-xs text-red-500 flex items-center gap-2">
                    <span className="material-icons text-xs">error</span>
                    {errors.confirmPassword}
                  </p>
                )}
                {errors.role && (
                  <p className="text-xs text-red-500 flex items-center gap-2">
                    <span className="material-icons text-xs">error</span>
                    {errors.role}
                  </p>
                )}
                {errors.assignedGeofence && (
                  <p className="text-xs text-red-500 flex items-center gap-2">
                    <span className="material-icons text-xs">error</span>
                    {errors.assignedGeofence}
                  </p>
                )}
              </div>
            )}

            {/* Register Button */}
            <Button
              type="submit"
              disabled={isLoading}
              className="w-full bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700 text-white py-6 text-base font-semibold shadow-xl hover:shadow-2xl transition-all duration-300 mt-6"
            >
              {isLoading ? (
                <>
                  <span className="material-icons animate-spin text-xl mr-2">refresh</span>
                  Creating Account...
                </>
              ) : (
                <>
                  <span className="material-icons text-xl mr-2">person_add</span>
                  Create Account
                </>
              )}
            </Button>
          </form>

          {/* Footer Links */}
          <div className="mt-6 pt-6 border-t border-border/50 text-center">
            <p className="text-xs text-white/70">
              Already have an account?{' '}
              <a
                href="/login"
                className="text-indigo-400 hover:text-indigo-300 font-medium transition-colors"
              >
                Sign In
              </a>
            </p>
          </div>

          {/* Security Badge */}
          <div className="mt-6 flex items-center justify-center gap-2 text-xs text-white/70">
            <span className="material-icons text-sm text-green-500">verified_user</span>
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

