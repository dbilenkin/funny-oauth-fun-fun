// src/Users.tsx
import React, { useEffect, useState } from 'react';
import axios from 'axios';

type User = {
  userId: string;
  email: string;
  name: string;
  createdAt: string;
  // Add other fields as needed
};

const Users: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [error, setError] = useState<string>('');

  const API_BASE_URL = 'https://hzkn0o3ly4.execute-api.us-east-2.amazonaws.com/prod';

  useEffect(() => {
    const fetchUsers = async () => {
      const token = localStorage.getItem('token'); // Adjust based on how you store the JWT

      if (!token) {
        setError('No authentication token found.');
        return;
      }

      try {
        const response = await axios.get(`${API_BASE_URL}/users`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        setUsers(response.data);
      } catch (err: any) {
        setError(err.response?.data?.error || 'Failed to fetch users.');
      }
    };

    fetchUsers();
  }, []);

  if (error) {
    return <div>Error: {error}</div>;
  }

  return (
    <div>
      <h1>Users List</h1>
      {users.length === 0 ? (
        <p>No users found.</p>
      ) : (
        <ul>
          {users.map(user => (
            <li key={user.userId}>
              <strong>{user.name}</strong> - {user.email} (Joined: {new Date(user.createdAt).toLocaleDateString()})
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

export default Users;
