import React from 'react';
import ReactDOM from 'react-dom/client';
import './styles/index.css';
import App from './App';

/**
 * This file is the entry point of the React application.
 * It renders the App component, which includes all functionality.
 * @file
 * @requires react
 */
const root = ReactDOM.createRoot(document.getElementById('root'));
//document.body.classList.add("dark-theme"); //!new 

root.render(
  <React.StrictMode>
    <App/>
  </React.StrictMode>
);
