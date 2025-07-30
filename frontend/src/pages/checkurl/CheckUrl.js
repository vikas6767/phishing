import axios from "axios";
import React, { useState } from "react";
import "./CheckUrl.css";
// Import icons for legitimate and phishing indicators
import LegitIcon from "../../assets/png/check24.png";
import PhishIcon from "../../assets/png/cross24.png";

function CheckUrl() {
  const [inputUrl, setInputUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showResults, setShowResults] = useState(false);
  const [resInfo, setResInfo] = useState({
    url: "",
    featureExtractionResult: Array(15).fill(0),
    predictionMade: 0,
    successRate: 0,
    phishRate: 0,
    detectionSource: ""
  });
  /* eslint-disable */
  const HTTP_URL_VALIDATOR_REGEX =
    /(http(s)?:\/\/.)?(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)/g;

  const checkLink = (string) => {
    return string.match(HTTP_URL_VALIDATOR_REGEX);
  };
  
  const checkUrlHandler = () => {
    setError("");
    setShowResults(false);

    if (!inputUrl) {
      setError("Please enter a URL");
      return;
    }

    const formattedUrl = inputUrl.startsWith('http://') || inputUrl.startsWith('https://') 
      ? inputUrl 
      : `https://${inputUrl}`;

    if (checkLink(formattedUrl)) {
      setLoading(true);
      // Use environment variable or fallback to local development server
      const apiUrl = process.env.REACT_APP_API_URL || 'http://localhost:8000';
      axios
        .get(
          `${apiUrl}/api/?url=${encodeURIComponent(formattedUrl)}`
        )
        .then((res) => {
          console.log(res.data);
          
          // Ensure the response has all required fields with defaults if missing
          const safeResponse = {
            url: res.data.url || formattedUrl,
            featureExtractionResult: res.data.featureExtractionResult || Array(15).fill(0),
            predictionMade: typeof res.data.predictionMade === 'number' ? res.data.predictionMade : 0,
            successRate: typeof res.data.successRate === 'number' ? res.data.successRate : 50,
            phishRate: typeof res.data.phishRate === 'number' ? res.data.phishRate : 50,
            detectionSource: res.data.detectionSource || "ml_model"
          };
          
          setResInfo(safeResponse);
          setLoading(false);
          setShowResults(true);
        })
        .catch((err) => {
          console.log(err);
          setLoading(false);
          setError("Error connecting to the server. Please make sure the backend is running.");
        });
    } else {
      console.log("not an url");
      setError("Please enter a valid URL including the protocol (http:// or https://)");
      setLoading(false);
    }
  };
  
  const loadExampleUrl = () => {
    setInputUrl("https://www.google.com");
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  // Safely access feature extraction result
  const getFeatureValue = (index) => {
    if (resInfo && 
        resInfo.featureExtractionResult && 
        Array.isArray(resInfo.featureExtractionResult) && 
        index < resInfo.featureExtractionResult.length) {
      return resInfo.featureExtractionResult[index];
    }
    return 0; // Default value if any condition fails
  };

  // Helper function to render feature indicator
  const renderFeatureIndicator = (value, isPositive) => {
    const showPositive = isPositive ? value === 1 : value === 0;
    return (
      <img
        className="feature-icon"
        src={showPositive ? LegitIcon : PhishIcon}
        alt={showPositive ? "legitimate" : "phishing"}
      />
    );
  };

  // Get a user-friendly name for the detection source
  const getDetectionSourceDisplay = (source) => {
    if (!source) return "Machine Learning Model";
    
    const sourceMap = {
      'ml_model': 'Machine Learning Model',
      'trusted_list': 'Trusted Domain List',
      'phishtank': 'PhishTank Database',
      'google_safebrowsing': 'Google Safe Browsing',
      'cached_phishing_list': 'Known Phishing Domain',
      'error_fallback': 'Error Recovery (Default)',
      'emergency_trusted_override': 'Verified Safe Domain',
      'openphish': 'OpenPhish Database',
      'urlhaus': 'URLhaus Database'
    };

    // For cache sources
    if (source.startsWith('cache_')) {
      const originalSource = source.replace('cache_', '');
      return `Cached: ${sourceMap[originalSource] || originalSource}`;
    }

    return sourceMap[source] || source;
  };

  return (
    <div className="url-analysis-page">
      <div className="url-analysis-header">
        <div className="icon">🌐</div>
        <h1 className="url-analysis-title">URL Analysis</h1>
      </div>
      <p className="url-analysis-description">
        Analyze URLs to detect phishing links, URL shorteners, and other suspicious patterns.
      </p>

      <div className="url-input-container">
        <div className="url-input-label">
          <span>URL to Analyze</span>
          <button className="load-example-btn" onClick={loadExampleUrl}>
            Load Example
          </button>
        </div>
        <div className="url-input-wrapper">
          <input
            type="text"
            className="url-input"
            value={inputUrl}
            onChange={(e) => setInputUrl(e.target.value)}
            placeholder="Enter a URL to analyze..."
          />
          <button className="search-btn" onClick={checkUrlHandler}>
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
              <path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" stroke="currentColor" fill="none"/>
            </svg>
          </button>
        </div>
        <p className="url-hint">Enter any URL you suspect might be phishing to analyze it.</p>
        {error && <p style={{ color: 'var(--danger-color)', marginTop: '0.5rem' }}>{error}</p>}
      </div>

      {loading && (
        <div className="loading-container">
          <div className="spinner"></div>
          <p>Analyzing URL security...</p>
        </div>
      )}

      {showResults && (
        <div className="results-container">
          <div className="results-header">
            <h2 className="results-title">URL Analysis Results</h2>
            <span className={`safety-tag ${resInfo.predictionMade === 0 ? 'safe-tag' : 'danger-tag'}`}>
              {resInfo.predictionMade === 0 ? 'Likely Safe' : 'Potentially Dangerous'}
            </span>
          </div>

          <div className="result-section">
            <div className="result-label">Original URL</div>
            <div className="result-content">
              <span className="result-text">{resInfo.url}</span>
              <button className="copy-btn" onClick={() => copyToClipboard(resInfo.url)}>
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path>
                </svg>
              </button>
            </div>
          </div>

          <div className="result-section">
            <div className="result-label">Domain</div>
            <div className="result-content">
              <span className="result-text">
                {(() => {
                  try {
                    const url = new URL(resInfo.url.startsWith('http') ? resInfo.url : `http://${resInfo.url}`);
                    return url.hostname;
                  } catch (e) {
                    return resInfo.url;
                  }
                })()}
              </span>
            </div>
          </div>

          <div className="result-section">
            <div className="result-label">Detection Method</div>
            <div className="result-content">
              <span className="result-text">
                {getDetectionSourceDisplay(resInfo.detectionSource)}
              </span>
            </div>
          </div>

          <div className="result-section">
            <div className="result-label">Analysis Result</div>
            <div className="result-content">
              <div className="confidence-meters">
                <div className="confidence-meter">
                  <span>Safe:</span>
                  <div className="meter-bar">
                    <div 
                      className="meter-fill safe" 
                      style={{width: `${resInfo.successRate}%`}}
                    ></div>
                  </div>
                  <span>{resInfo.successRate}%</span>
                </div>
                <div className="confidence-meter">
                  <span>Suspicious:</span>
                  <div className="meter-bar">
                    <div 
                      className="meter-fill danger" 
                      style={{width: `${resInfo.phishRate}%`}}
                    ></div>
                  </div>
                  <span>{resInfo.phishRate}%</span>
                </div>
              </div>
            </div>
          </div>

          <div className="safety-tips">
            <h3 className="safety-tips-title">Safety Tips</h3>
            <ul className="tips-list">
              <li className="tip-item">
                <span className="tip-bullet">●</span>
                Always check the domain name carefully before entering credentials
              </li>
              <li className="tip-item">
                <span className="tip-bullet">●</span>
                Be wary of URLs containing brand names with hyphens or misspellings
              </li>
              <li className="tip-item">
                <span className="tip-bullet">●</span>
                Don't trust shortened URLs in emails or messages from unknown senders
              </li>
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}

export default CheckUrl;
