'use client';

import { ProfileCard } from '@/components/profile/profile-card';
import { ProfileEditor } from '@/components/profile/profile-editor';
import { LoginHistory } from '@/components/profile/login-history';

export default function ProfilePage() {
  return (
    <div className="space-y-6">
      {/* Header Section */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">My Profile</h1>
          <p className="text-muted-foreground mt-1">Manage your personal information and preferences</p>
        </div>
      </div>

      {/* Profile Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Profile Card */}
        <div className="lg:col-span-1">
          <ProfileCard />
        </div>

        {/* Right: Profile Editor */}
        <div className="lg:col-span-2">
          <ProfileEditor />
        </div>
      </div>

      {/* Login History */}
      <LoginHistory />
    </div>
  );
}


























