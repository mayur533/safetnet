import { NotificationsContainer } from '@/components/notifications/notifications-container';

export default function NotificationsPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Notifications</h1>
          <p className="text-muted-foreground">Manage all your security alerts and system notifications</p>
        </div>
      </div>
      
      <NotificationsContainer />
    </div>
  );
}























