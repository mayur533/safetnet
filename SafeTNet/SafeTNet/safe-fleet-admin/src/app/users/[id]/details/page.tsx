'use client';

import { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { userDetailsService, type UserDetail } from '@/lib/services/user-details';
import { usersService, type User } from '@/lib/services/users';

export default function UserDetailsPage() {
  const params = useParams();
  const router = useRouter();
  const userId = parseInt(params.id as string);
  
  const [user, setUser] = useState<User | null>(null);
  const [userDetails, setUserDetails] = useState<UserDetail | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetchData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId]);

  const fetchData = async () => {
    try {
      setIsLoading(true);
      const [userData, detailsData] = await Promise.all([
        usersService.getById(userId),
        userDetailsService.getByUserId(userId)
      ]);
      setUser(userData);
      setUserDetails(detailsData);
    } catch (error: unknown) {
      console.error('Error fetching data:', error);
      toast.error('Failed to load user details');
    } finally {
      setIsLoading(false);
    }
  };

  const formatDate = (dateString?: string) => {
    if (!dateString) return 'Not set';
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        {/* Header Skeleton */}
        <div className="flex items-center gap-4">
          <div className="h-10 w-24 bg-muted rounded animate-pulse"></div>
          <div className="space-y-2">
            <div className="h-8 w-48 bg-muted rounded animate-pulse"></div>
            <div className="h-4 w-96 bg-muted rounded animate-pulse"></div>
          </div>
        </div>

        {/* User Profile Card Skeleton */}
        <div className="h-40 bg-muted rounded-lg animate-pulse"></div>

        {/* Details Grid Skeleton */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-80 bg-muted rounded-lg animate-pulse"></div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header with Back Button */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button
            variant="outline"
            onClick={() => router.back()}
            className="gap-2"
          >
            <span className="material-icons text-sm">arrow_back</span>
            Back
          </Button>
          <div>
            <h1 className="text-3xl font-bold">User Details</h1>
            {user && (
              <p className="text-muted-foreground mt-1">
                Additional information for {user.full_name || user.username}
              </p>
            )}
          </div>
        </div>
      </div>

      {/* User Profile Card */}
      {user && (
        <Card className="p-6 bg-gradient-to-r from-indigo-50 to-blue-50 dark:from-indigo-950/30 dark:to-blue-950/30 border-indigo-200 dark:border-indigo-800">
          <div className="flex items-center gap-6">
            {userDetails?.profile_image ? (
              // eslint-disable-next-line @next/next/no-img-element
              <img 
                src={userDetails.profile_image} 
                alt={user.username}
                className="w-24 h-24 rounded-full object-cover border-4 border-white dark:border-gray-800"
              />
            ) : (
              <div className="w-24 h-24 rounded-full bg-gradient-to-br from-indigo-600 to-blue-600 flex items-center justify-center text-white text-4xl font-bold border-4 border-white dark:border-gray-800">
                {(user.full_name || user.username).charAt(0).toUpperCase()}
              </div>
            )}
            <div className="flex-1">
              <h2 className="text-2xl font-bold">{user.full_name || user.username}</h2>
              <p className="text-muted-foreground">{user.email}</p>
              <div className="flex items-center gap-4 mt-2">
                <span className="text-sm bg-white/60 dark:bg-black/30 px-3 py-1 rounded-full">
                  {user.role}
                </span>
                <span className={`text-sm px-3 py-1 rounded-full ${
                  user.is_active 
                    ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' 
                    : 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-400'
                }`}>
                  {user.is_active ? 'Active' : 'Inactive'}
                </span>
                {user.organization && (
                  <span className="text-sm bg-white/60 dark:bg-black/30 px-3 py-1 rounded-full flex items-center gap-1">
                    <span className="material-icons text-xs">business</span>
                    {user.organization.name}
                  </span>
                )}
              </div>
            </div>
          </div>
        </Card>
      )}

      {userDetails ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Personal Information */}
          <Card className="p-6">
            <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
              <span className="material-icons text-indigo-600">person</span>
              Personal Information
            </h3>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-sm text-muted-foreground">Username</Label>
                  <p className="font-medium mt-1">{user?.username}</p>
                </div>
                <div>
                  <Label className="text-sm text-muted-foreground">Email</Label>
                  <p className="font-medium mt-1">{user?.email}</p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-sm text-muted-foreground">Phone Number</Label>
                  <p className="font-medium mt-1">{userDetails.phone_number || 'Not set'}</p>
                </div>
                <div>
                  <Label className="text-sm text-muted-foreground">Date of Birth</Label>
                  <p className="font-medium mt-1">{formatDate(userDetails.date_of_birth)}</p>
                </div>
              </div>

              {userDetails.bio && (
                <div>
                  <Label className="text-sm text-muted-foreground">Bio</Label>
                  <p className="font-medium mt-1 text-sm bg-muted/30 p-3 rounded-lg">
                    {userDetails.bio}
                  </p>
                </div>
              )}
            </div>
          </Card>

          {/* Address Information */}
          <Card className="p-6">
            <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
              <span className="material-icons text-indigo-600">location_on</span>
              Address Information
            </h3>
            <div className="space-y-4">
              <div>
                <Label className="text-sm text-muted-foreground">Street Address</Label>
                <p className="font-medium mt-1">{userDetails.address || 'Not set'}</p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-sm text-muted-foreground">City</Label>
                  <p className="font-medium mt-1">{userDetails.city || 'Not set'}</p>
                </div>
                <div>
                  <Label className="text-sm text-muted-foreground">State</Label>
                  <p className="font-medium mt-1">{userDetails.state || 'Not set'}</p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-sm text-muted-foreground">ZIP Code</Label>
                  <p className="font-medium mt-1">{userDetails.zip_code || 'Not set'}</p>
                </div>
                <div>
                  <Label className="text-sm text-muted-foreground">Country</Label>
                  <p className="font-medium mt-1">{userDetails.country || 'Not set'}</p>
                </div>
              </div>
            </div>
          </Card>

          {/* Account Information */}
          <Card className="p-6">
            <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
              <span className="material-icons text-indigo-600">account_circle</span>
              Account Information
            </h3>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-sm text-muted-foreground">User ID</Label>
                  <p className="font-mono text-sm mt-1">{user?.id}</p>
                </div>
                <div>
                  <Label className="text-sm text-muted-foreground">Details ID</Label>
                  <p className="font-mono text-sm mt-1">{userDetails.id}</p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-sm text-muted-foreground">Date Joined</Label>
                  <p className="font-medium mt-1">{formatDate(user?.date_joined)}</p>
                </div>
                <div>
                  <Label className="text-sm text-muted-foreground">Last Login</Label>
                  <p className="font-medium mt-1">{formatDate(user?.last_login || undefined)}</p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-sm text-muted-foreground">Details Created</Label>
                  <p className="font-medium mt-1">{formatDate(userDetails.created_at)}</p>
                </div>
                <div>
                  <Label className="text-sm text-muted-foreground">Last Updated</Label>
                  <p className="font-medium mt-1">{formatDate(userDetails.updated_at)}</p>
                </div>
              </div>
            </div>
          </Card>

          {/* Preferences & Metadata */}
          {(userDetails.preferences || userDetails.metadata) && (
            <Card className="p-6">
              <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
                <span className="material-icons text-indigo-600">settings</span>
                Preferences & Metadata
              </h3>
              <div className="space-y-4">
                {userDetails.preferences && Object.keys(userDetails.preferences).length > 0 && (
                  <div>
                    <Label className="text-sm text-muted-foreground">Preferences</Label>
                    <div className="mt-2 bg-muted/30 p-3 rounded-lg">
                      <pre className="text-xs overflow-auto">
                        {JSON.stringify(userDetails.preferences, null, 2)}
                      </pre>
                    </div>
                  </div>
                )}

                {userDetails.metadata && Object.keys(userDetails.metadata).length > 0 && (
                  <div>
                    <Label className="text-sm text-muted-foreground">Metadata</Label>
                    <div className="mt-2 bg-muted/30 p-3 rounded-lg">
                      <pre className="text-xs overflow-auto">
                        {JSON.stringify(userDetails.metadata, null, 2)}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            </Card>
          )}
        </div>
      ) : (
        <Card className="p-12">
          <div className="text-center text-muted-foreground">
            <span className="material-icons text-6xl mb-4 opacity-50">info</span>
            <p className="text-lg">No additional details found for this user</p>
            <p className="text-sm mt-2">Extended user information has not been set up for this account yet.</p>
          </div>
        </Card>
      )}
    </div>
  );
}

