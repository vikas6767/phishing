import React, { useState } from 'react';
import axios from 'axios';
import { Container, Card, Form, Button, Alert, Spinner, Badge, Row, Col, Table, Nav, Tab } from 'react-bootstrap';
import './EmailAnalysis.css';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const EmailAnalysis = () => {
  const [formData, setFormData] = useState({
    sender: '',
    subject: '',
    body: ''
  });
  
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value
    });
  };
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);
    
    try {
      const response = await axios.post(`${API_URL}/analyze_email/`, formData);
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.error || 'An error occurred while analyzing the email');
    } finally {
      setLoading(false);
    }
  };
  
  const getBadgeVariant = (risk) => {
    if (risk === 'High Risk') return 'danger';
    if (risk === 'Medium Risk') return 'warning';
    if (risk === 'Low Risk') return 'info';
    return 'success';
  };
  
  const getProgressBarVariant = (score) => {
    if (score >= 75) return 'danger';
    if (score >= 40) return 'warning';
    if (score >= 15) return 'info';
    return 'success';
  };
  
  const renderAuthenticationSection = () => {
    if (!result) return null;
    
    const { header_analysis } = result;
    const authResults = header_analysis.authentication_results;
    
    return (
      <Card className="mt-4 email-auth-card">
        <Card.Header>
          <h5>Email Authentication</h5>
        </Card.Header>
        <Card.Body>
          <div className="d-flex justify-content-around">
            <div className="text-center auth-indicator">
              <h6>SPF</h6>
              <Badge bg={authResults.spf === 'pass' ? 'success' : 'danger'}>
                {authResults.spf || 'Not Found'}
              </Badge>
            </div>
            <div className="text-center auth-indicator">
              <h6>DKIM</h6>
              <Badge bg={authResults.dkim === 'pass' ? 'success' : 'danger'}>
                {authResults.dkim || 'Not Found'}
              </Badge>
            </div>
            <div className="text-center auth-indicator">
              <h6>DMARC</h6>
              <Badge bg={authResults.dmarc === 'pass' ? 'success' : 'danger'}>
                {authResults.dmarc || 'Not Found'}
              </Badge>
            </div>
          </div>
        </Card.Body>
      </Card>
    );
  };
  
  const renderHeaderAnalysis = () => {
    if (!result) return null;
    
    const { header_analysis } = result;
    
    return (
      <div>
        {renderAuthenticationSection()}
        
        <Card className="mt-4">
          <Card.Header>
            <h5>Email Headers</h5>
          </Card.Header>
          <Card.Body>
            <Table striped bordered hover responsive>
              <thead>
                <tr>
                  <th>Header</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>From</td>
                  <td>{header_analysis.parsed_headers.from || 'N/A'}</td>
                </tr>
                <tr>
                  <td>To</td>
                  <td>{header_analysis.parsed_headers.to || 'N/A'}</td>
                </tr>
                <tr>
                  <td>Subject</td>
                  <td>{header_analysis.parsed_headers.subject || 'N/A'}</td>
                </tr>
                <tr>
                  <td>Date</td>
                  <td>{header_analysis.parsed_headers.date || 'N/A'}</td>
                </tr>
                <tr>
                  <td>Reply-To</td>
                  <td>{header_analysis.parsed_headers.reply_to || 'N/A'}</td>
                </tr>
                <tr>
                  <td>Return-Path</td>
                  <td>{header_analysis.parsed_headers.return_path || 'N/A'}</td>
                </tr>
              </tbody>
            </Table>
          </Card.Body>
        </Card>
      </div>
    );
  };
  
  const renderContentAnalysis = () => {
    if (!result) return null;
    
    const { content_analysis } = result;
    
    return (
      <div>
        <Card className="mt-4">
          <Card.Header>
            <h5>Social Engineering Tactics</h5>
          </Card.Header>
          <Card.Body>
            {content_analysis.social_engineering_tactics.length > 0 ? (
              <div className="d-flex flex-wrap">
                {content_analysis.social_engineering_tactics.map((tactic, index) => (
                  <Badge key={index} bg="danger" className="m-1 p-2 tactic-badge">
                    {tactic.charAt(0).toUpperCase() + tactic.slice(1)}
                  </Badge>
                ))}
              </div>
            ) : (
              <p>No social engineering tactics detected</p>
            )}
          </Card.Body>
        </Card>
        
        <Card className="mt-4">
          <Card.Header>
            <h5>Detected URLs</h5>
          </Card.Header>
          <Card.Body>
            {content_analysis.extracted_urls.length > 0 ? (
              <Table striped bordered hover responsive>
                <thead>
                  <tr>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {content_analysis.extracted_urls.map((url, index) => (
                    <tr key={index}>
                      <td className="url-cell">{url.url}</td>
                      <td>
                        <Badge bg={url.suspicious ? 'danger' : 'success'}>
                          {url.suspicious ? 'Suspicious' : 'Safe'}
                        </Badge>
                      </td>
                      <td>{url.reason || 'N/A'}</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            ) : (
              <p>No URLs detected in email content</p>
            )}
          </Card.Body>
        </Card>
      </div>
    );
  };
  
  const renderSuspiciousIndicators = () => {
    if (!result) return null;
    
    const { header_analysis, content_analysis } = result;
    const allIndicators = [
      ...header_analysis.suspicious_indicators.map(i => ({ ...i, source: 'Header' })),
      ...content_analysis.suspicious_indicators.map(i => ({ ...i, source: 'Content' }))
    ];
    
    return (
      <div>
        <Card className="mt-4">
          <Card.Header>
            <h5>Suspicious Indicators</h5>
          </Card.Header>
          <Card.Body>
            {allIndicators.length > 0 ? (
              <Table striped bordered hover responsive>
                <thead>
                  <tr>
                    <th>Source</th>
                    <th>Type</th>
                    <th>Name</th>
                    <th>Description</th>
                    <th>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {allIndicators.map((indicator, index) => (
                    <tr key={index}>
                      <td>{indicator.source}</td>
                      <td>{indicator.type}</td>
                      <td>{indicator.name}</td>
                      <td>{indicator.description}</td>
                      <td>
                        <Badge 
                          bg={
                            indicator.severity === 'high' ? 'danger' : 
                            indicator.severity === 'medium' ? 'warning' : 'info'
                          }
                        >
                          {indicator.severity}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            ) : (
              <p>No suspicious indicators detected</p>
            )}
          </Card.Body>
        </Card>
      </div>
    );
  };
  
  const renderResultSummary = () => {
    if (!result) return null;
    
    return (
      <Card className="mt-4 mb-4 result-summary-card">
        <Card.Header>
          <h4 className="text-center">Analysis Result</h4>
        </Card.Header>
        <Card.Body>
          <div className="text-center mb-4">
            <h5>Overall Risk Level</h5>
            <Badge
              pill
              bg={getBadgeVariant(result.risk_level)}
              className="risk-badge"
            >
              {result.risk_level}
            </Badge>
            
            <div className="mt-4">
              <h5>Risk Score: {Math.round(result.combined_risk_score)}/100</h5>
              <div className="progress" style={{ height: '30px' }}>
                <div
                  className={`progress-bar bg-${getProgressBarVariant(result.combined_risk_score)}`}
                  role="progressbar"
                  style={{ width: `${result.combined_risk_score}%` }}
                  aria-valuenow={result.combined_risk_score}
                  aria-valuemin="0"
                  aria-valuemax="100"
                >
                  {Math.round(result.combined_risk_score)}%
                </div>
              </div>
            </div>
          </div>
          
          <Row className="mt-4">
            <Col md={6}>
              <div className="text-center">
                <h5>Header Risk Score</h5>
                <Badge
                  pill
                  bg={getBadgeVariant(result.header_analysis.risk_level)}
                  className="score-badge"
                >
                  {result.header_analysis.risk_score}/100
                </Badge>
              </div>
            </Col>
            <Col md={6}>
              <div className="text-center">
                <h5>Content Risk Score</h5>
                <Badge
                  pill
                  bg={getBadgeVariant(result.content_analysis.risk_level)}
                  className="score-badge"
                >
                  {result.content_analysis.risk_score}/100
                </Badge>
              </div>
            </Col>
          </Row>
        </Card.Body>
      </Card>
    );
  };
  
  return (
    <div className="email-analysis-wrapper">
      <Container className="py-4">
        <div className="email-content-analysis">
          <h2 className="analysis-title">
            <i className="bi bi-envelope"></i> Email Content Analysis
          </h2>
          <p className="analysis-description">
            Analyze email content for common phishing indicators and get a risk assessment.
          </p>
          
          <div className="analysis-form">
            <form onSubmit={handleSubmit}>
              <div className="form-field">
                <label htmlFor="sender">Sender Email Address</label>
                <input
                  type="text"
                  id="sender"
                  name="sender"
                  className="form-control"
                  placeholder="e.g., security@microsoft-secure.com"
                  value={formData.sender}
                  onChange={handleChange}
                  required
                />
              </div>
              
              <div className="form-field">
                <label htmlFor="subject">Email Subject</label>
                <input
                  type="text"
                  id="subject"
                  name="subject"
                  className="form-control"
                  placeholder="e.g., URGENT: Your account has been compromised"
                  value={formData.subject}
                  onChange={handleChange}
                  required
                />
              </div>
              
              <div className="form-field">
                <label htmlFor="body">Email Body Content</label>
                <textarea
                  id="body"
                  name="body"
                  className="form-control"
                  placeholder="Paste the email content here..."
                  value={formData.body}
                  onChange={handleChange}
                  rows={10}
                  required
                />
              </div>
              
              <button 
                type="submit" 
                className="analyze-button"
                disabled={loading}
              >
                {loading ? (
                  <><Spinner size="sm" animation="border" /> Analyzing...</>
                ) : (
                  <>Analyze Email</>
                )}
              </button>
            </form>
          </div>
          
          {error && (
            <Alert variant="danger" className="mt-4">
              {error}
            </Alert>
          )}
          
          {result && (
            <div className="analysis-results">
              {renderResultSummary()}
              <Tab.Container defaultActiveKey="summary">
                <Nav variant="tabs" className="analysis-tabs mt-4">
                  <Nav.Item>
                    <Nav.Link eventKey="summary">Summary</Nav.Link>
                  </Nav.Item>
                  <Nav.Item>
                    <Nav.Link eventKey="headers">Headers</Nav.Link>
                  </Nav.Item>
                  <Nav.Item>
                    <Nav.Link eventKey="content">Content</Nav.Link>
                  </Nav.Item>
                  <Nav.Item>
                    <Nav.Link eventKey="indicators">Indicators</Nav.Link>
                  </Nav.Item>
                </Nav>
                <Tab.Content>
                  <Tab.Pane eventKey="summary">
                    {/* The summary is already rendered above the tabs */}
                  </Tab.Pane>
                  <Tab.Pane eventKey="headers">
                    {renderHeaderAnalysis()}
                  </Tab.Pane>
                  <Tab.Pane eventKey="content">
                    {renderContentAnalysis()}
                  </Tab.Pane>
                  <Tab.Pane eventKey="indicators">
                    {renderSuspiciousIndicators()}
                  </Tab.Pane>
                </Tab.Content>
              </Tab.Container>
            </div>
          )}
        </div>
      </Container>
    </div>
  );
};

export default EmailAnalysis; 