// src/pages/Profile.tsx

import React from 'react';

interface ProfileProps {
  user: User;
}

interface User {
  id?: string;
  email?: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  locale?: string;
}

const Profile: React.FC<ProfileProps> = ({ user }) => {
  return (
    <div className="p-8 flex flex-col items-center bg-gray-100 dark:bg-gray-900 min-h-screen">
      <h2 className="text-2xl font-semibold mb-4 text-white bg-blue-600 dark:bg-blue-800 px-4 py-2 rounded">
        Profile
      </h2>
      {user.picture && (
        <img
          src={user.picture}
          alt="Profile"
          className="rounded-full mb-4 w-32 h-32 object-cover border-4 border-blue-600 dark:border-blue-800"
        />
      )}
      <div className="text-lg text-gray-700 dark:text-gray-300">
        <p><strong>Name:</strong> {user.name}</p>
        <p><strong>Email:</strong> {user.email}</p>
      </div>
    </div>
  );
};

export default Profile;
