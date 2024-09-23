import React, { useEffect, useState } from 'react';
import axios from 'axios';

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
        .get('http://localhost:8080/user', {
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
    window.location.href = 'http://localhost:8080/login';
  };

  const handleLogout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
  };

  return (
    <div className="App">
      <h1>React Google OAuth Example with JWT</h1>
      {user ? (
        <div>
          <h2>Welcome, {user.name}!</h2>
          {user.picture && <img src={user.picture} alt="Profile" />}
          <p>Email: {user.email}</p>
          <button onClick={handleLogout}>Logout</button>
        </div>
      ) : (
        <button onClick={handleLogin}>Login with Google</button>
      )}
    </div>
  );
};

export default App;
