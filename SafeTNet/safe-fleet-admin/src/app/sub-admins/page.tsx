'use client';

import { useState } from 'react';
import { SubAdminsTable } from '@/components/sub-admins/sub-admins-table';
import { AddSubAdminModal } from '@/components/sub-admins/add-subadmin-modal';
import { EditSubAdminModal } from '@/components/sub-admins/edit-subadmin-modal';
import { Button } from '@/components/ui/button';

export default function SubAdminsPage() {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [editingSubAdmin, setEditingSubAdmin] = useState<number | null>(null);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  const handleEditSubAdmin = (subAdminId: number) => {
    setEditingSubAdmin(subAdminId);
    setIsEditModalOpen(true);
  };

  const handleSubAdminUpdated = () => {
    setRefreshTrigger(prev => prev + 1);
  };

  return (
    <div className="space-y-6">
      {/* Header Section */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Sub-Admin Management</h1>
          <p className="text-muted-foreground mt-1">Manage and oversee all sub-administrators</p>
        </div>
        <Button
          onClick={() => setIsModalOpen(true)}
          className="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-2.5 rounded-lg font-medium shadow-lg hover:shadow-xl transition-all duration-200"
        >
          <span className="material-icons text-xl mr-2">add</span>
          Add Sub-Admin
        </Button>
      </div>

      {/* Sub-Admins Table */}
      <SubAdminsTable 
        onEditSubAdmin={handleEditSubAdmin}
        refreshTrigger={refreshTrigger}
      />

      {/* Add Sub-Admin Modal */}
      <AddSubAdminModal
        isOpen={isModalOpen}
        onClose={() => {
          setIsModalOpen(false);
          setRefreshTrigger(prev => prev + 1);
        }}
      />

      {/* Edit Sub-Admin Modal */}
      <EditSubAdminModal
        isOpen={isEditModalOpen}
        onClose={() => {
          setIsEditModalOpen(false);
          setEditingSubAdmin(null);
        }}
        userId={editingSubAdmin}
        onSubAdminUpdated={handleSubAdminUpdated}
      />
    </div>
  );
}



