'use client';

import { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { userRepliesService, type UserReply } from '@/lib/services/user-replies';
import { usersService, type User } from '@/lib/services/users';

export default function UserRepliesPage() {
  const params = useParams();
  const router = useRouter();
  const userId = parseInt(params.id as string);
  
  const [user, setUser] = useState<User | null>(null);
  const [replies, setReplies] = useState<UserReply[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetchData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId]);

  const fetchData = async () => {
    try {
      setIsLoading(true);
      const [userData, repliesData] = await Promise.all([
        usersService.getById(userId),
        userRepliesService.getByUserId(userId)
      ]);
      setUser(userData);
      setReplies(repliesData);
    } catch (error: unknown) {
      console.error('Error fetching data:', error);
      toast.error('Failed to load user replies');
    } finally {
      setIsLoading(false);
    }
  };

  const getStatusBadge = (status: string) => {
    const statusConfig = {
      PENDING: { color: 'bg-yellow-100 text-yellow-800 border-yellow-200', label: 'Pending' },
      REVIEWED: { color: 'bg-blue-100 text-blue-800 border-blue-200', label: 'Reviewed' },
      RESOLVED: { color: 'bg-green-100 text-green-800 border-green-200', label: 'Resolved' },
    };

    const config = statusConfig[status as keyof typeof statusConfig] || statusConfig.PENDING;

    return (
      <Badge variant="outline" className={`${config.color} border`}>
        {config.label}
      </Badge>
    );
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
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

        {/* User Card Skeleton */}
        <div className="h-32 bg-muted rounded-lg animate-pulse"></div>

        {/* Stats Cards Skeleton */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-28 bg-muted rounded-lg animate-pulse"></div>
          ))}
        </div>

        {/* Title Skeleton */}
        <div className="h-8 w-64 bg-muted rounded animate-pulse"></div>

        {/* Replies Skeleton */}
        <div className="space-y-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-48 bg-muted rounded-lg animate-pulse"></div>
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
            <h1 className="text-3xl font-bold">User Replies</h1>
            {user && (
              <p className="text-muted-foreground mt-1">
                Viewing replies from {user.full_name || user.username} ({user.email})
              </p>
            )}
          </div>
        </div>
      </div>

      {/* User Info Card */}
      {user && (
        <Card className="p-6 bg-gradient-to-r from-indigo-50 to-blue-50 dark:from-indigo-950/30 dark:to-blue-950/30 border-indigo-200 dark:border-indigo-800">
          <div className="flex items-center gap-4">
            <div className="w-16 h-16 rounded-full bg-gradient-to-br from-indigo-600 to-blue-600 flex items-center justify-center text-white text-2xl font-bold">
              {(user.full_name || user.username).charAt(0).toUpperCase()}
            </div>
            <div>
              <h2 className="text-xl font-semibold">{user.full_name || user.username}</h2>
              <p className="text-sm text-muted-foreground">{user.email}</p>
              <div className="flex items-center gap-2 mt-1">
                <span className="text-sm">Role: {user.role}</span>
                <span className="text-muted-foreground">•</span>
                <span className="text-sm">
                  {user.is_active ? (
                    <span className="text-green-600 flex items-center gap-1">
                      <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                      Active
                    </span>
                  ) : (
                    <span className="text-gray-600 flex items-center gap-1">
                      <span className="w-2 h-2 bg-gray-500 rounded-full"></span>
                      Inactive
                    </span>
                  )}
                </span>
              </div>
            </div>
          </div>
        </Card>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Total Replies</p>
              <p className="text-3xl font-bold mt-1">{replies.length}</p>
            </div>
            <div className="w-12 h-12 rounded-full bg-indigo-100 dark:bg-indigo-900/30 flex items-center justify-center">
              <span className="material-icons text-indigo-600 dark:text-indigo-400">message</span>
            </div>
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Pending</p>
              <p className="text-3xl font-bold mt-1">
                {replies.filter(r => r.status === 'PENDING').length}
              </p>
            </div>
            <div className="w-12 h-12 rounded-full bg-yellow-100 dark:bg-yellow-900/30 flex items-center justify-center">
              <span className="material-icons text-yellow-600 dark:text-yellow-400">schedule</span>
            </div>
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Resolved</p>
              <p className="text-3xl font-bold mt-1">
                {replies.filter(r => r.status === 'RESOLVED').length}
              </p>
            </div>
            <div className="w-12 h-12 rounded-full bg-green-100 dark:bg-green-900/30 flex items-center justify-center">
              <span className="material-icons text-green-600 dark:text-green-400">check_circle</span>
            </div>
          </div>
        </Card>
      </div>

      {/* Replies List */}
      <div className="space-y-4">
        <h2 className="text-xl font-semibold flex items-center gap-2">
          <span className="material-icons">forum</span>
          All Replies ({replies.length})
        </h2>

        {replies.length === 0 ? (
          <Card className="p-12">
            <div className="text-center text-muted-foreground">
              <span className="material-icons text-6xl mb-4 opacity-50">inbox</span>
              <p className="text-lg">No replies found for this user</p>
              <p className="text-sm mt-2">This user hasn&apos;t submitted any feedback or replies yet.</p>
            </div>
          </Card>
        ) : (
          <div className="space-y-4">
            {replies.map((reply) => (
              <Card key={reply.id} className="p-6 hover:shadow-lg transition-shadow">
                <div className="space-y-4">
                  {/* Header */}
                  <div className="flex items-start justify-between">
                    <div className="space-y-1">
                      <h3 className="text-lg font-semibold flex items-center gap-2">
                        <span className="material-icons text-sm text-indigo-600">subject</span>
                        {reply.subject}
                      </h3>
                      {reply.reply_type && (
                        <Badge variant="outline" className="text-xs">
                          {reply.reply_type}
                        </Badge>
                      )}
                    </div>
                    {getStatusBadge(reply.status)}
                  </div>

                  {/* Message */}
                  <div className="bg-muted/30 p-4 rounded-lg">
                    <p className="text-sm whitespace-pre-wrap">{reply.message}</p>
                  </div>

                  {/* Footer */}
                  <div className="flex items-center justify-between text-sm text-muted-foreground pt-2 border-t">
                    <div className="flex items-center gap-4">
                      <span className="flex items-center gap-1">
                        <span className="material-icons text-xs">calendar_today</span>
                        {formatDate(reply.created_at)}
                      </span>
                      <span className="flex items-center gap-1">
                        <span className="material-icons text-xs">tag</span>
                        ID: {reply.id}
                      </span>
                    </div>
                    {reply.updated_at !== reply.created_at && (
                      <span className="text-xs">
                        Updated: {formatDate(reply.updated_at)}
                      </span>
                    )}
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

