'use client';

import { useState, useEffect } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
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
import { toast } from 'sonner';
import { organizationsService } from '@/lib/services/organizations';
import { usersService } from '@/lib/services/users';
import { LoadingDots } from '@/components/ui/loading-dots';

interface AddSubAdminModalProps {
  isOpen: boolean;
  onClose: () => void;
}

interface Organization {
  id: number;
  name: string;
}

export function AddSubAdminModal({ isOpen, onClose }: AddSubAdminModalProps) {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    confirmPassword: '',
    assignedArea: '',
    organization: '',
  });

  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Fetch organizations when modal opens
  useEffect(() => {
    const fetchOrganizations = async () => {
      if (!isOpen) return;
      try {
        const orgs = await organizationsService.getAll();
        setOrganizations(orgs);
      } catch (error) {
        console.error('Failed to fetch organizations:', error);
        // Silently fail - 403 errors are expected for users without access
        setOrganizations([]);
      }
    };
    
    fetchOrganizations();
  }, [isOpen]);

  const handleChange = (field: string, value: string) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
    // Clear error when user starts typing
    if (errors[field]) {
      setErrors((prev) => ({ ...prev, [field]: '' }));
    }
  };

  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    if (!formData.name.trim()) {
      newErrors.name = 'Name is required';
    }

    if (!formData.email.trim()) {
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

      if (!formData.organization) {
      newErrors.organization = 'Please select an organization';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    if (isSubmitting) {
      return; // Prevent double submission
    }

    setIsSubmitting(true);

    try {
      // Split name into first and last name
      const nameParts = formData.name.trim().split(' ');
      const firstName = nameParts[0] || '';
      const lastName = nameParts.slice(1).join(' ') || '';
      
      // Use users API to create SUB_ADMIN
      await usersService.create({
        username: formData.email.split('@')[0],
        email: formData.email,
        password: formData.password,
        first_name: firstName,
        last_name: lastName,
        role: 'SUB_ADMIN',
        organization: formData.organization ? parseInt(formData.organization) : null,
      });

      // Reset form
      setFormData({
        name: '',
        email: '',
        password: '',
        confirmPassword: '',
        assignedArea: '',
        organization: '',
      });
      setErrors({});

      toast.success('Sub-admin created successfully!');
      onClose();
    } catch (error) {
      console.error('Sub-admin creation error:', error);
      toast.error('Failed to create sub-admin');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleClose = () => {
    setFormData({
      name: '',
      email: '',
      password: '',
      confirmPassword: '',
      assignedArea: '',
      organization: '',
    });
    setErrors({});
    onClose();
  };

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-[550px] bg-card/95 backdrop-blur-xl border-border/50">
        <DialogHeader>
          <DialogTitle className="text-2xl font-bold flex items-center">
            <span className="material-icons text-indigo-600 mr-2">person_add</span>
            Add New Sub-Admin
          </DialogTitle>
          <DialogDescription>
            Create a new sub-administrator account with assigned security area
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-5 mt-4">
          {/* Name Field */}
          <div className="space-y-2">
            <Label htmlFor="name" className="text-sm font-medium">
              Full Name <span className="text-red-500">*</span>
            </Label>
            <div className="relative">
              <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-lg">
                person
              </span>
              <Input
                id="name"
                type="text"
                placeholder="Enter full name"
                value={formData.name}
                onChange={(e) => handleChange('name', e.target.value)}
                className={`pl-10 ${errors.name ? 'border-red-500' : ''}`}
              />
            </div>
            {errors.name && <p className="text-xs text-red-500 mt-1">{errors.name}</p>}
          </div>

          {/* Email Field */}
          <div className="space-y-2">
            <Label htmlFor="email" className="text-sm font-medium">
              Email Address <span className="text-red-500">*</span>
            </Label>
            <div className="relative">
              <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-lg">
                email
              </span>
              <Input
                id="email"
                type="email"
                placeholder="subadmin@safefleet.com"
                value={formData.email}
                onChange={(e) => handleChange('email', e.target.value)}
                className={`pl-10 ${errors.email ? 'border-red-500' : ''}`}
              />
            </div>
            {errors.email && <p className="text-xs text-red-500 mt-1">{errors.email}</p>}
          </div>

          {/* Password Fields */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="password" className="text-sm font-medium">
                Password <span className="text-red-500">*</span>
              </Label>
              <div className="relative">
                <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-lg">
                  lock
                </span>
                <Input
                  id="password"
                  type="password"
                  placeholder="Min. 8 characters"
                  value={formData.password}
                  onChange={(e) => handleChange('password', e.target.value)}
                  className={`pl-10 ${errors.password ? 'border-red-500' : ''}`}
                />
              </div>
              {errors.password && <p className="text-xs text-red-500 mt-1">{errors.password}</p>}
            </div>

            <div className="space-y-2">
              <Label htmlFor="confirmPassword" className="text-sm font-medium">
                Confirm Password <span className="text-red-500">*</span>
              </Label>
              <div className="relative">
                <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-lg">
                  lock_outline
                </span>
                <Input
                  id="confirmPassword"
                  type="password"
                  placeholder="Re-enter password"
                  value={formData.confirmPassword}
                  onChange={(e) => handleChange('confirmPassword', e.target.value)}
                  className={`pl-10 ${errors.confirmPassword ? 'border-red-500' : ''}`}
                />
              </div>
              {errors.confirmPassword && (
                <p className="text-xs text-red-500 mt-1">{errors.confirmPassword}</p>
              )}
            </div>
          </div>

          {/* Organization Selection */}
          <div className="space-y-2">
            <Label htmlFor="organization" className="text-sm font-medium">
              Organization <span className="text-red-500">*</span>
            </Label>
            <div className="relative">
              <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-lg z-10">
                business
              </span>
              <Select
                value={formData.organization}
                onValueChange={(value) => handleChange('organization', value)}
              >
                <SelectTrigger className={`pl-10 ${errors.organization ? 'border-red-500' : ''}`}>
                  <SelectValue placeholder="Select organization" />
                </SelectTrigger>
                <SelectContent>
                  {organizations.map((org) => (
                    <SelectItem key={org.id} value={org.id.toString()}>
                      {org.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {errors.organization && (
              <p className="text-xs text-red-500 mt-1">{errors.organization}</p>
            )}
          </div>

          {/* Info Box */}
          <div className="bg-indigo-50 dark:bg-indigo-950/20 border border-indigo-200 dark:border-indigo-800 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <span className="material-icons text-indigo-600 text-xl">info</span>
              <div className="flex-1">
                <p className="text-sm text-indigo-900 dark:text-indigo-100 font-medium">
                  Sub-Admin Permissions
                </p>
                <p className="text-xs text-indigo-700 dark:text-indigo-300 mt-1">
                  Sub-admins can manage geofences, security officers, and send notifications within
                  their assigned area.
                </p>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex justify-end space-x-3 pt-4 border-t">
            <Button
              type="button"
              variant="outline"
              onClick={handleClose}
              disabled={isSubmitting}
              className="px-6"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={isSubmitting}
              className="bg-indigo-600 hover:bg-indigo-700 text-white px-6"
            >
              {isSubmitting ? (
                <>
                  <LoadingDots />
                  <span className="ml-2">Creating</span>
                </>
              ) : (
                <>
                  <span className="material-icons text-sm mr-2">check</span>
                  Create Sub-Admin
                </>
              )}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}









