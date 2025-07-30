import React from "react";
import { Link } from "react-router-dom";
import Summary from "../summary/Summary";
import "./Head.css";

function Head() {
  return (
    <div className="hero-section">
      <div className="hero-content text-center">
        <div className="max-w">
          <h1 className="main-title">PhishGuard</h1>
          <p className="hero-description">
            Advanced detection system to identify phishing websites and emails using machine learning and reputation analysis.
          </p>

          <div className="action-buttons">
            <Link to="/checkurl">
              <button className="btn btn-primary action-button">
                Check URL
              </button>
            </Link>
            <Link to="/features">
              <button className="btn btn-outline-primary action-button">
                Features
              </button>
            </Link>
          </div>
          
          <Summary />
        </div>
      </div>
    </div>
  );
}

export default Head;
