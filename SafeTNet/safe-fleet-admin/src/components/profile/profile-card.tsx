'use client';

import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/lib/contexts/auth-context';
import { profileService } from '@/lib/services/profile';
import { getRoleDisplayLabel } from '@/lib/utils/role-converter';
import { toast } from 'sonner';

export function ProfileCard() {
  const { user, logout } = useAuth();
  const [profileImage, setProfileImage] = useState<string | null>(null);
  const [profileData, setProfileData] = useState(user);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    // Fetch fresh profile data
    const fetchProfile = async () => {
      try {
        setIsLoading(true);
        const profile = await profileService.getProfile();
        setProfileData(profile);
      } catch (error) {
        console.error('Failed to fetch profile:', error);
        // Use cached user data if API fails
        setProfileData(user);
      } finally {
        setIsLoading(false);
      }
    };

    fetchProfile();
  }, [user]);

  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onloadend = () => {
        setProfileImage(reader.result as string);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleSignOut = async () => {
    await logout();
    toast.success('Signed out successfully');
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  };

  return (
    <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
      {/* Profile Picture */}
      <div className="flex flex-col items-center">
        <div className="relative group">
          {profileImage ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img
              src={profileImage}
              alt="Profile"
              className="w-32 h-32 rounded-full object-cover border-4 border-gradient-to-r from-indigo-500 to-blue-500 shadow-lg"
            />
          ) : (
            <div className="w-32 h-32 rounded-full bg-gradient-to-br from-indigo-500 to-blue-600 flex items-center justify-center text-white shadow-lg">
              <span className="material-icons" style={{ fontSize: '64px' }}>
                person
              </span>
            </div>
          )}
          
          {/* Upload Button Overlay */}
          <label
            htmlFor="profile-upload"
            className="absolute inset-0 flex items-center justify-center bg-black/50 rounded-full opacity-0 group-hover:opacity-100 transition-opacity cursor-pointer"
          >
            <span className="material-icons text-white text-2xl">photo_camera</span>
          </label>
          <input
            id="profile-upload"
            type="file"
            accept="image/*"
            onChange={handleImageUpload}
            className="hidden"
          />
        </div>

        {isLoading ? (
          <div className="mt-4">
            <div className="h-6 w-32 bg-muted animate-pulse rounded"></div>
            <div className="h-4 w-40 bg-muted animate-pulse rounded mt-2"></div>
          </div>
        ) : (
          <>
            <h2 className="text-xl font-bold mt-4">{profileData?.username || 'User'}</h2>
            <p className="text-sm text-muted-foreground">{profileData?.email || 'No email'}</p>

            {/* Role Badge */}
            <div className="mt-3">
              <span className="inline-flex items-center px-4 py-1.5 rounded-full text-xs font-medium bg-gradient-to-r from-purple-500 to-indigo-600 text-white shadow-lg">
                <span className="material-icons text-sm mr-1">admin_panel_settings</span>
                {profileData?.role ? getRoleDisplayLabel(profileData.role) : 'USER'}
              </span>
            </div>
          </>
        )}
      </div>

      {/* Divider */}
      <div className="my-6 border-t border-border/50"></div>

      {/* Profile Info */}
      <div className="space-y-4">
        <div>
          <p className="text-xs text-muted-foreground uppercase font-semibold mb-2">Account Info</p>
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <span className="material-icons text-sm text-indigo-600">badge</span>
              <div className="flex-1">
                <p className="text-xs text-muted-foreground">User ID</p>
                <p className="text-sm font-medium">#{profileData?.id || 'N/A'}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <span className="material-icons text-sm text-indigo-600">calendar_today</span>
              <div className="flex-1">
                <p className="text-xs text-muted-foreground">Member Since</p>
                <p className="text-sm font-medium">
                  {profileData?.date_joined ? formatDate(profileData.date_joined) : 'N/A'}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <span className="material-icons text-sm text-indigo-600">verified_user</span>
              <div className="flex-1">
                <p className="text-xs text-muted-foreground">Account Status</p>
                <p className="text-sm font-medium">
                  {profileData?.is_active ? (
                    <span className="text-green-600">Active</span>
                  ) : (
                    <span className="text-red-600">Inactive</span>
                  )}
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="pt-3 border-t border-border/50">
          <p className="text-xs text-muted-foreground uppercase font-semibold mb-2">
            Assigned Geofences
          </p>
          <div className="space-y-2">
            <div className="flex items-center gap-2 px-3 py-2 bg-muted/50 rounded-lg">
              <span className="w-2 h-2 rounded-full bg-indigo-500"></span>
              <span className="text-xs">All Zones (Admin Access)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="mt-6 pt-6 border-t border-border/50">
        <Button
          variant="outline"
          className="w-full text-xs"
          onClick={handleSignOut}
        >
          <span className="material-icons text-sm mr-2">logout</span>
          Sign Out
        </Button>
      </div>
    </div>
  );
}

