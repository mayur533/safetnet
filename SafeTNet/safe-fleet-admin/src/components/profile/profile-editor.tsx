'use client';

import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useAuth } from '@/lib/contexts/auth-context';
import { profileService } from '@/lib/services/profile';
import { toast } from 'sonner';
import { LoadingDots } from '@/components/ui/loading-dots';

export function ProfileEditor() {
  const { user } = useAuth();
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [phone, setPhone] = useState('+1 (555) 123-4567');
  const [address, setAddress] = useState('123 Security Street, Safe City, SC 12345');
  const [showPasswordChange, setShowPasswordChange] = useState(false);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    if (user) {
      setUsername(user.username || '');
      setEmail(user.email || '');
      setFullName(user.username || ''); // Backend doesn't have full_name in response, use username
    }
  }, [user]);

  const handleSave = async () => {
    setIsSaving(true);
    try {
      await profileService.updateProfile({
        username,
        email,
        full_name: fullName,
      });
      toast.success('Profile updated successfully!');
    } catch (error: unknown) {
      console.error('Profile update error:', error);
      toast.error('Failed to update profile');
    } finally {
      setIsSaving(false);
    }
  };

  const handlePasswordChange = async () => {
    if (newPassword !== confirmPassword) {
      toast.error('New passwords do not match');
      return;
    }

    setIsSaving(true);
    try {
      await profileService.changePassword({
        old_password: currentPassword,
        new_password: newPassword,
        confirm_password: confirmPassword,
      });
      toast.success('Password changed successfully!');
      setShowPasswordChange(false);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (error: unknown) {
      console.error('Password change error:', error);
      toast.error('Failed to change password');
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6 pb-4 border-b border-border/50">
        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-indigo-500 to-blue-600 flex items-center justify-center shadow-lg">
          <span className="material-icons text-white text-xl">edit</span>
        </div>
        <div>
          <h3 className="font-semibold text-lg">Edit Profile</h3>
          <p className="text-xs text-muted-foreground">Update your personal information</p>
        </div>
      </div>

      {/* Form */}
      <div className="space-y-5">
        {/* Full Name */}
        <div className="flex items-center justify-between">
          <Label htmlFor="fullName" className="text-sm font-medium">
            Full Name
          </Label>
          <div className="relative w-96">
            <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-lg">
              person
            </span>
            <Input
              id="fullName"
              type="text"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              className="pl-10"
            />
          </div>
        </div>

        {/* Email */}
        <div className="flex items-center justify-between pt-3 border-t border-border/50">
          <Label htmlFor="email" className="text-sm font-medium">
            Email Address
          </Label>
          <div className="relative w-96">
            <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-lg">
              email
            </span>
            <Input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="pl-10"
            />
          </div>
        </div>

        {/* Phone */}
        <div className="flex items-center justify-between pt-3 border-t border-border/50">
          <Label htmlFor="phone" className="text-sm font-medium">
            Phone Number
          </Label>
          <div className="relative w-96">
            <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-lg">
              phone
            </span>
            <Input
              id="phone"
              type="tel"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              className="pl-10"
            />
          </div>
        </div>

        {/* Address */}
        <div className="flex items-start justify-between pt-3 border-t border-border/50">
          <Label htmlFor="address" className="text-sm font-medium mt-2">
            Address
          </Label>
          <div className="relative w-96">
            <span className="material-icons absolute left-3 top-3 text-muted-foreground text-lg">
              location_on
            </span>
            <textarea
              id="address"
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              className="w-full pl-10 pr-4 py-2 min-h-[80px] rounded-md border border-input bg-background text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            />
          </div>
        </div>

        {/* Password Change Section */}
        <div className="pt-3 border-t border-border/50">
          <div className="flex items-center justify-between mb-4">
            <Label className="text-sm font-medium">Password</Label>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowPasswordChange(!showPasswordChange)}
              className="text-xs"
            >
              <span className="material-icons text-sm mr-1">
                {showPasswordChange ? 'visibility_off' : 'lock_reset'}
              </span>
              {showPasswordChange ? 'Cancel' : 'Change Password'}
            </Button>
          </div>

          {showPasswordChange && (
            <div className="space-y-4 bg-muted/20 p-4 rounded-lg border border-border/50">
              <div className="space-y-2">
                <Label htmlFor="currentPassword" className="text-xs text-muted-foreground">
                  Current Password
                </Label>
                <div className="relative">
                  <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-base">
                    lock
                  </span>
                  <Input
                    id="currentPassword"
                    type="password"
                    placeholder="Enter current password"
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    className="pl-10 text-sm"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="newPassword" className="text-xs text-muted-foreground">
                  New Password
                </Label>
                <div className="relative">
                  <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-base">
                    lock_reset
                  </span>
                  <Input
                    id="newPassword"
                    type="password"
                    placeholder="Min. 8 characters"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="pl-10 text-sm"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="confirmPassword" className="text-xs text-muted-foreground">
                  Confirm New Password
                </Label>
                <div className="relative">
                  <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-base">
                    lock_outline
                  </span>
                  <Input
                    id="confirmPassword"
                    type="password"
                    placeholder="Re-enter new password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="pl-10 text-sm"
                  />
                </div>
              </div>

              {/* Change Password Button */}
              <div className="pt-2">
                <Button
                  onClick={handlePasswordChange}
                  disabled={isSaving || !currentPassword || !newPassword || !confirmPassword}
                  className="w-full bg-gradient-to-r from-orange-600 to-red-600 hover:from-orange-700 hover:to-red-700 text-white"
                  size="sm"
                >
                  {isSaving ? (
                    <>
                      <LoadingDots />
                      <span className="ml-2">Updating</span>
                    </>
                  ) : (
                    <>
                      <span className="material-icons text-sm mr-2">lock_reset</span>
                      Update Password
                    </>
                  )}
                </Button>
              </div>
            </div>
          )}
        </div>

        {/* Save Button */}
        <div className="pt-6">
          <Button
            onClick={handleSave}
            disabled={isSaving}
            className="w-full bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700 text-white shadow-lg hover:shadow-xl transition-all"
          >
            {isSaving ? (
              <>
                <LoadingDots />
                <span className="ml-2">Saving Changes</span>
              </>
            ) : (
              <>
                <span className="material-icons text-sm mr-2">save</span>
                Save Changes
              </>
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}

