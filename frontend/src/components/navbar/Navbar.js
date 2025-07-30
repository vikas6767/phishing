import React from "react";
import { Link, useLocation } from "react-router-dom";
import ThemeToggle from "../themeToggle/ThemeToggle";
import "./Navbar.css";

function Navbar() {
  const location = useLocation();
  
  return (
    <div className="custom-navbar">
      <div className="navbar-logo">
        <Link to="/" className="brand-name">
          PhishGuard
        </Link>
      </div>
      <ul className="nav-links">
        <li className="nav-item">
          <Link 
            to="/" 
            className={`nav-link ${location.pathname === '/' || location.pathname === '/checkurl' ? 'active' : ''}`}
          >
            URL Analysis
          </Link>
        </li>
        <li className="nav-item">
          <Link 
            to="/email-analysis" 
            className={`nav-link ${location.pathname === '/email-analysis' ? 'active' : ''}`}
          >
            Email Analysis
          </Link>
        </li>
        <li className="nav-item">
          <Link 
            to="/dashboard" 
            className={`nav-link ${location.pathname === '/dashboard' ? 'active' : ''}`}
          >
            <i className="bi bi-shield-lock"></i> Dashboard
          </Link>
        </li>
        <li className="nav-item">
          <Link 
            to="/password-checker" 
            className={`nav-link ${location.pathname === '/password-checker' ? 'active' : ''}`}
          >
            <i className="bi bi-key"></i> Password Checker
          </Link>
        </li>
      </ul>
      <div className="navbar-right">
        <ThemeToggle />
      </div>
    </div>
  );
}

export default Navbar;
