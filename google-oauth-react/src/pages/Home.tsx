// src/pages/Home.tsx

import React from 'react';

const Home: React.FC = () => {
  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-100 dark:bg-gray-900">
      <h1 className="text-4xl justify-center font-bold mb-4 text-blue-600 dark:text-blue-400">Funny OAuth Fun Fun</h1>
      <p className="text-lg text-gray-700 dark:text-gray-300">Login to see stuff!</p>
    </div>
  );
};

export default Home;
