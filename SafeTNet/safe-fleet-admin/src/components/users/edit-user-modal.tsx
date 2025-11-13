'use client';

import { useState, useEffect } from 'react';
import { toast } from 'sonner';
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
import { Switch } from '@/components/ui/switch';
import { usersService } from '@/lib/services/users';
import { LoadingDots } from '@/components/ui/loading-dots';

interface EditUserModalProps {
  isOpen: boolean;
  onClose: () => void;
  userId: number | null;
  onUserUpdated?: () => void;
}

export function EditUserModal({ isOpen, onClose, userId, onUserUpdated }: EditUserModalProps) {
  const [formData, setFormData] = useState({
    username: '',
    firstName: '',
    lastName: '',
    email: '',
    isActive: true,
  });

  const [errors, setErrors] = useState<Record<string, string>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isLoadingUser, setIsLoadingUser] = useState(false);

  useEffect(() => {
    if (userId && isOpen) {
      fetchUserData(userId);
    } else if (!isOpen) {
      // Reset form when modal closes
      setFormData({
        username: '',
        firstName: '',
        lastName: '',
        email: '',
        isActive: true,
      });
      setErrors({});
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId, isOpen]);

  const fetchUserData = async (id: number) => {
    try {
      setIsLoadingUser(true);
      const user = await usersService.getById(id);
      setFormData({
        username: user.username,
        firstName: user.first_name || '',
        lastName: user.last_name || '',
        email: user.email,
        isActive: user.is_active,
      });
    } catch (error) {
      console.error('Failed to fetch user:', error);
      toast.error('Failed to load user data');
      onClose();
    } finally {
      setIsLoadingUser(false);
    }
  };

  const handleChange = (field: string, value: string | boolean) => {
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

    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = 'Invalid email format';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm() || !userId) {
      return;
    }

    try {
      setIsSubmitting(true);

      await usersService.update(userId, {
        username: formData.username,
        first_name: formData.firstName,
        last_name: formData.lastName,
        email: formData.email,
        is_active: formData.isActive,
      });

      toast.success('User updated successfully');
      onUserUpdated?.();
      onClose();
    } catch (error) {
      console.error('Update error:', error);
      toast.error('Failed to update user');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-[600px] bg-card/95 backdrop-blur-xl border-border/50 max-h-[90vh] overflow-y-auto p-4">
        <DialogHeader>
          <DialogTitle className="text-2xl font-bold flex items-center bg-gradient-to-r from-indigo-600 to-blue-600 bg-clip-text text-transparent">
            <span className="material-icons text-indigo-600 mr-2">
              edit
            </span>
            Edit User
          </DialogTitle>
          <DialogDescription>
            Update user information and permissions
          </DialogDescription>
        </DialogHeader>

        {isLoadingUser ? (
          <div className="py-8 text-center">
            <div className="inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-current border-r-transparent"></div>
            <p className="mt-2 text-sm text-muted-foreground">Loading user data...</p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4 mt-3">
            {/* Username */}
            <div className="space-y-2">
              <Label htmlFor="username" className="text-sm font-medium">
                Username <span className="text-red-500">*</span>
              </Label>
              <div className="relative">
                <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-lg">
                  badge
                </span>
                <Input
                  id="username"
                  type="text"
                  placeholder="Enter username"
                  value={formData.username}
                  onChange={(e) => handleChange('username', e.target.value)}
                  className={`pl-10 ${errors.username ? 'border-red-500' : ''}`}
                />
              </div>
              {errors.username && <p className="text-xs text-red-500 mt-1">{errors.username}</p>}
            </div>

            {/* First Name & Last Name */}
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="firstName" className="text-sm font-medium">First Name</Label>
                <div className="relative">
                  <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-lg">
                    person
                  </span>
                  <Input
                    id="firstName"
                    type="text"
                    placeholder="First name"
                    value={formData.firstName}
                    onChange={(e) => handleChange('firstName', e.target.value)}
                    className="pl-10"
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="lastName" className="text-sm font-medium">Last Name</Label>
                <div className="relative">
                  <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-lg">
                    person_outline
                  </span>
                  <Input
                    id="lastName"
                    type="text"
                    placeholder="Last name"
                    value={formData.lastName}
                    onChange={(e) => handleChange('lastName', e.target.value)}
                    className="pl-10"
                  />
                </div>
              </div>
            </div>

            {/* Email */}
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
                  placeholder="user@safetnet.com"
                  value={formData.email}
                  onChange={(e) => handleChange('email', e.target.value)}
                  className={`pl-10 ${errors.email ? 'border-red-500' : ''}`}
                />
              </div>
              {errors.email && <p className="text-xs text-red-500 mt-1">{errors.email}</p>}
            </div>

            {/* Active Status */}
            <div className="space-y-2">
              <Label htmlFor="isActive" className="text-sm font-medium">Account Status</Label>
              <div className="flex items-center justify-between p-4 bg-muted/30 rounded-lg border">
                <div className="flex items-center gap-3">
                  <span className="material-icons text-muted-foreground">
                    {formData.isActive ? 'check_circle' : 'cancel'}
                  </span>
                  <div>
                    <p className="font-medium">
                      {formData.isActive ? 'Active' : 'Inactive'}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {formData.isActive ? 'User can access the system' : 'User is blocked from accessing the system'}
                    </p>
                  </div>
                </div>
                <Switch
                  id="isActive"
                  checked={formData.isActive}
                  onCheckedChange={(checked) => handleChange('isActive', checked)}
                />
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex justify-end gap-3 pt-3 border-t mt-4">
              <Button
                type="button"
                variant="outline"
                onClick={onClose}
                disabled={isSubmitting}
                className="px-6"
              >
                <span className="material-icons text-sm mr-2" style={{ lineHeight: '0', verticalAlign: 'baseline', marginBottom: '-2px' }}>close</span>
                Cancel
              </Button>
              <Button 
                type="submit" 
                disabled={isSubmitting}
                className="px-6 bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700"
              >
                {isSubmitting ? (
                  <>
                    <LoadingDots />
                    <span className="ml-2">Updating</span>
                  </>
                ) : (
                  <>
                    <span className="material-icons mr-2 text-sm" style={{ lineHeight: '0', verticalAlign: 'baseline', marginBottom: '-2px' }}>check_circle</span>
                    Update User
                  </>
                )}
              </Button>
            </div>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

