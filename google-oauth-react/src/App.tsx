// src/App.tsx

import React, { useEffect, useState } from 'react';
import axios from 'axios';
import {
  BrowserRouter as Router,
  Routes,
  Route,
} from 'react-router-dom';
import Navbar from './components/Navbar';
import ProtectedRoute from './components/ProtectedRoute';
import Home from './pages/Home';
import Users from './pages/Users';
import Profile from './pages/Profile'; // Optional

interface User {
  id?: string;
  email?: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  locale?: string;
}

const App: React.FC = () => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);

  const API_BASE_URL = 'https://hzkn0o3ly4.execute-api.us-east-2.amazonaws.com/prod';

  useEffect(() => {
    // Check if token is in URL parameters
    const params = new URLSearchParams(window.location.search);
    const tokenParam = params.get('token');
    if (tokenParam) {
      // Remove token from URL
      window.history.replaceState({}, document.title, '/');

      setToken(tokenParam);
      localStorage.setItem('token', tokenParam);
    } else {
      const storedToken = localStorage.getItem('token');
      if (storedToken) {
        setToken(storedToken);
      }
    }
  }, []);

  useEffect(() => {
    if (token) {
      // Fetch user data from the backend
      axios
        .get(`${API_BASE_URL}/user`, {
          headers: { Authorization: `Bearer ${token}` },
        })
        .then((response) => {
          setUser(response.data);
        })
        .catch((error) => {
          console.error('Not authenticated', error);
          setUser(null);
          setToken(null);
          localStorage.removeItem('token');
        });
    }
  }, [token]);

  const handleLogin = () => {
    window.location.href = `${API_BASE_URL}/login`;
  };

  const handleLogout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
  };

  return (
    <Router>
      {/* Add 'dark' class to enable dark mode */}
      <div className="flex flex-col min-h-screen bg-gray-100 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
        <Navbar user={user} handleLogin={handleLogin} handleLogout={handleLogout} />
        <div className="flex-grow container mx-auto px-4">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route
              path="/users"
              element={
                <ProtectedRoute user={user}>
                  <Users />
                </ProtectedRoute>
              }
            />
            <Route
              path="/profile"
              element={
                <ProtectedRoute user={user}>
                  {/* Non-Null Assertion */}
                  <Profile user={user!} />
                </ProtectedRoute>
              }
            />
            {/* Add more routes as needed */}
            <Route path="*" element={<NotFound />} />
          </Routes>
        </div>
        <footer className="bg-gray-200 dark:bg-gray-800 text-center p-4">
          &copy; {new Date().getFullYear()} OAuthApp. All rights reserved.
        </footer>
      </div>
    </Router>
  );
};

// Optional: NotFound Component
const NotFound: React.FC = () => {
  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-100 dark:bg-gray-900">
      <h1 className="text-4xl font-bold mb-4">404 - Not Found</h1>
      <p className="text-lg text-gray-700 dark:text-gray-300">The page you are looking for does not exist.</p>
    </div>
  );
};

export default App;
