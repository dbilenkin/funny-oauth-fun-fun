// src/components/Navbar.tsx

import React from 'react';
import { Link } from 'react-router-dom';

interface NavbarProps {
  user: User | null;
  handleLogin: () => void;
  handleLogout: () => void;
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

const Navbar: React.FC<NavbarProps> = ({ user, handleLogin, handleLogout }) => {
  return (
    <nav className="bg-blue-600 dark:bg-blue-800 p-4">
      <div className="container mx-auto flex justify-between items-center">
        <div className='flex items-center'>
          {/* Logo */}
          <Link to="/" className="text-white font-semibold text-lg px-2">
            OAuthApp
          </Link>

          {/* Navigation Links */}
          <Link
            to="/"
            className="text-white hover:bg-blue-700 dark:hover:bg-blue-700 px-2 py-2 rounded transition duration-300"
          >
            Home
          </Link>
          {user && (
            <>
              <Link
                to="/users"
                className="text-white hover:bg-blue-700 dark:hover:bg-blue-700 px-2 py-2 rounded transition duration-300"
              >
                Users
              </Link>

              <Link
                to="/profile"
                className="text-white hover:bg-blue-700 dark:hover:bg-blue-700 px-2 py-2 rounded transition duration-300"
              >
                Profile
              </Link>
            </>
          )}
        </div>

        {/* Login/Logout Button */}
        <div>
          {user ? (
            <button
              onClick={handleLogout}
              className="bg-red-500 hover:bg-red-700 dark:hover:bg-red-700 text-white font-bold py-2 px-4 rounded flex items-center"
              aria-label="Logout"
            >
              {/* Logout Icon */}
              <svg
                xmlns="http://www.w3.org/2000/svg"
                className="w-5 h-5"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h6a2 2 0 012 2v1"
                />
              </svg>
              {/* Text: Hidden on small screens */}
              <span className="ml-2 hidden sm:inline">Logout</span>
            </button>
          ) : (
            <button
              onClick={handleLogin}
              className="bg-white hover:bg-gray-100 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-800 dark:text-gray-200 font-bold py-2 px-4 rounded flex items-center"
              aria-label="Login with Google"
            >
              {/* Google Icon */}
              <svg
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 48 48"
                className="w-5 h-5"
              >
                <path
                  fill="#4285F4"
                  d="M24 9.5c3.38 0 6.44 1.31 8.85 3.52l6.65-6.65C35.56 2.55 30.4 0 24 0 14.58 0 6.78 5.85 2.95 14.09l7.05 5.49C12.72 14.63 17.8 9.5 24 9.5z"
                />
                <path
                  fill="#34A853"
                  d="M46.98 24.55c0-1.63-.15-3.21-.43-4.73H24v9.01h12.96c-.57 3.07-2.23 5.67-4.75 7.4l7.62 5.91c4.44-4.09 6.98-10.14 6.98-17.59z"
                />
                <path
                  fill="#FBBC05"
                  d="M10.45 28.21c-.36-1.07-.56-2.2-.56-3.36 0-1.16.2-2.29.56-3.36L2.95 14.09C0.93 17.48 0 21.21 0 24c0 2.79.93 6.52 2.95 9.91l7.5-5.7z"
                />
                <path
                  fill="#EA4335"
                  d="M24 48c6.4 0 11.56-2.55 15.43-6.94l-7.62-5.91c-2.52 1.73-5.58 2.76-7.81 2.76-6.2 0-11.28-5.13-12.94-12.05l-7.05 5.49C6.78 42.15 14.58 48 24 48z"
                />
                <path fill="none" d="M0 0h48v48H0z" />
              </svg>
              {/* Text: Hidden on small screens */}
              <span className="hidden sm:inline ml-2">Login with Google</span>
            </button>
          )}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
