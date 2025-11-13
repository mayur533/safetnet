'use client';

import { useState } from 'react';
import { UsersTable } from '@/components/users/users-table';
import { EditUserModal } from '@/components/users/edit-user-modal';
import { AddUserModal } from '@/components/users/add-user-modal';
import { Button } from '@/components/ui/button';

export default function UsersPage() {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<number | null>(null);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  const handleAddUser = () => {
    setIsAddModalOpen(true);
  };

  const handleEditUser = (userId: number) => {
    setEditingUser(userId);
    setIsModalOpen(true);
  };

  const handleUserUpdated = () => {
    setRefreshTrigger(prev => prev + 1);
    setIsAddModalOpen(false);
  };

  return (
    <div className="space-y-6">
      {/* Header Section */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">User Management</h1>
          <p className="text-muted-foreground mt-1">Manage all users and their access permissions</p>
        </div>
        <Button
          onClick={handleAddUser}
          className="bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700 text-white px-6 py-2.5 rounded-lg font-medium shadow-lg hover:shadow-xl transition-all duration-200"
        >
          <span className="material-icons text-xl mr-2">person_add</span>
          Add User
        </Button>
      </div>

      {/* Users Table - has its own loading state */}
      <UsersTable onEditUser={handleEditUser} refreshTrigger={refreshTrigger} />

      {/* Add User Modal */}
      <AddUserModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        editingUserId={null}
        onUserUpdated={handleUserUpdated}
      />

      {/* Edit User Modal */}
      <EditUserModal
        isOpen={isModalOpen}
        onClose={() => {
          setIsModalOpen(false);
          setEditingUser(null);
        }}
        userId={editingUser}
        onUserUpdated={handleUserUpdated}
      />
    </div>
  );
}



