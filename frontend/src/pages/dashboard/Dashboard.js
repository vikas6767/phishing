import React, { useState, useEffect } from 'react';
import { Container, Row, Col, Card, Table, Badge, ProgressBar } from 'react-bootstrap';
import './Dashboard.css';
import { useNotification } from '../../context/NotificationContext';

const Dashboard = () => {
  const [attackData, setAttackData] = useState([]);
  const [threatLevel, setThreatLevel] = useState(75);
  const [isLoading, setIsLoading] = useState(true);
  const [scanHistory, setScanHistory] = useState([]);
  const { notifyDanger, notifyWarning, notifySuccess, notifyInfo } = useNotification();

  // Mock attack data
  const mockAttacks = [
    { id: 1, date: '2023-05-22 01:15', type: 'Phishing', target: 'Banking Sector', severity: 'High', origin: 'Eastern Europe', status: 'Active' },
    { id: 2, date: '2023-05-22 00:42', type: 'DDoS', target: 'E-commerce', severity: 'Critical', origin: 'Southeast Asia', status: 'Active' },
    { id: 3, date: '2023-05-21 23:11', type: 'Ransomware', target: 'Healthcare', severity: 'Critical', origin: 'North America', status: 'Contained' },
    { id: 4, date: '2023-05-21 19:30', type: 'Data Breach', target: 'Social Media', severity: 'High', origin: 'Unknown', status: 'Investigating' },
    { id: 5, date: '2023-05-21 15:47', type: 'SQL Injection', target: 'Government', severity: 'Medium', origin: 'South America', status: 'Contained' },
    { id: 6, date: '2023-05-21 12:19', type: 'XSS', target: 'Education', severity: 'Medium', origin: 'Western Europe', status: 'Resolved' },
    { id: 7, date: '2023-05-21 09:05', type: 'Credential Stuffing', target: 'Entertainment', severity: 'High', origin: 'East Asia', status: 'Contained' },
  ];

  // Mock scan history data
  const mockScanHistory = [
    { id: 1, timestamp: '2023-05-22 10:15', type: 'URL', target: 'https://secure-banklogin.com', result: 'Phishing', riskScore: 95 },
    { id: 2, timestamp: '2023-05-22 09:30', type: 'Email', target: 'urgent_payment@secure-bank-verify.com', result: 'Phishing', riskScore: 90 },
    { id: 3, timestamp: '2023-05-21 18:22', type: 'URL', target: 'https://google.com', result: 'Legitimate', riskScore: 5 },
    { id: 4, timestamp: '2023-05-21 16:45', type: 'Email', target: 'newsletter@amazon.com', result: 'Legitimate', riskScore: 10 },
    { id: 5, timestamp: '2023-05-21 14:12', type: 'URL', target: 'https://account-verify-paypal.net', result: 'Phishing', riskScore: 88 },
    { id: 6, timestamp: '2023-05-20 11:30', type: 'Email', target: 'support@microsoft.com', result: 'Legitimate', riskScore: 2 },
    { id: 7, timestamp: '2023-05-20 10:05', type: 'URL', target: 'https://netflix-account-update.info', result: 'Phishing', riskScore: 92 },
  ];

  // Mock threat notifications
  const mockNotifications = [
    { 
      title: 'Critical Threat Detected',
      message: 'Ransomware attack targeting healthcare sector detected. Multiple systems at risk.',
      type: 'danger',
      actionLabel: 'View Details'
    },
    {
      title: 'Suspicious Login Activity',
      message: 'Multiple login attempts detected from unusual location (IP: 203.87.123.44)',
      type: 'warning'
    },
    {
      title: 'Phishing Campaign Detected',
      message: 'New phishing campaign targeting banking customers. Email contains malicious attachment.',
      type: 'danger'
    },
    {
      title: 'System Update Required',
      message: 'Critical security patch available for your system. Please update immediately.',
      type: 'info',
      actionLabel: 'Update Now'
    }
  ];

  // Prevention measures
  const preventionMeasures = [
    { id: 1, threat: 'Phishing', measure: 'Implement DMARC, SPF and DKIM email authentication protocols', effectiveness: 85 },
    { id: 2, threat: 'DDoS', measure: 'Deploy anti-DDoS services and traffic filtering at network edge', effectiveness: 90 },
    { id: 3, threat: 'Ransomware', measure: 'Regular backups and offline storage with proper network segmentation', effectiveness: 80 },
    { id: 4, threat: 'Data Breach', measure: 'Encrypt sensitive data and implement strict access controls', effectiveness: 75 },
    { id: 5, threat: 'SQL Injection', measure: 'Use parameterized queries and input validation', effectiveness: 95 },
  ];

  // Get badge variant based on severity
  const getBadgeVariant = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'danger';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'secondary';
    }
  };

  // Get badge variant based on status
  const getStatusBadge = (status) => {
    switch (status.toLowerCase()) {
      case 'active': return 'danger';
      case 'investigating': return 'warning';
      case 'contained': return 'info';
      case 'resolved': return 'success';
      default: return 'secondary';
    }
  };

  // Get badge variant based on scan result
  const getResultBadge = (result) => {
    switch (result.toLowerCase()) {
      case 'phishing': return 'danger';
      case 'suspicious': return 'warning';
      case 'legitimate': return 'success';
      default: return 'secondary';
    }
  };

  // Show initial notifications
  useEffect(() => {
    if (!isLoading) {
      // Show initial notifications with a slight delay
      const notificationTimer = setTimeout(() => {
        // Show first notification immediately
        notifyDanger(
          mockNotifications[0].title, 
          mockNotifications[0].message, 
          { autoDismiss: false, actionLabel: mockNotifications[0].actionLabel, action: () => console.log('Action clicked') }
        );
        
        // Show second notification after 3 seconds
        setTimeout(() => {
          notifyWarning(
            mockNotifications[1].title,
            mockNotifications[1].message
          );
        }, 3000);
        
        // Show third notification after 8 seconds
        setTimeout(() => {
          notifyDanger(
            mockNotifications[2].title,
            mockNotifications[2].message
          );
        }, 8000);
        
        // Show fourth notification after 15 seconds
        setTimeout(() => {
          notifyInfo(
            mockNotifications[3].title,
            mockNotifications[3].message,
            { actionLabel: mockNotifications[3].actionLabel, action: () => console.log('Update clicked') }
          );
        }, 15000);
      }, 2000);

      return () => {
        clearTimeout(notificationTimer);
      };
    }
  }, [isLoading, notifyDanger, notifyWarning, notifyInfo]);

  // Simulate loading data
  useEffect(() => {
    const timer = setTimeout(() => {
      setAttackData(mockAttacks);
      setScanHistory(mockScanHistory);
      setIsLoading(false);

      // Simulate real-time updates
      const interval = setInterval(() => {
        setThreatLevel(prevLevel => {
          const change = Math.random() > 0.5 ? Math.random() * 5 : -Math.random() * 5;
          const newLevel = Math.min(Math.max(prevLevel + change, 40), 90);
          
          // Show notification if threat level exceeds 85
          if (newLevel > 85 && prevLevel <= 85) {
            notifyDanger(
              'High Threat Level Alert', 
              `The current threat level has increased to ${Math.round(newLevel)}%. Take immediate action to secure your systems.`,
              { autoDismiss: false }
            );
          }
          
          return newLevel;
        });
        
        // Randomly add a new attack (10% chance)
        if (Math.random() < 0.1) {
          const newAttackTypes = ['Phishing', 'DDoS', 'Ransomware', 'Malware', 'Zero-day Exploit'];
          const newSectors = ['Financial', 'Healthcare', 'Government', 'Education', 'Retail'];
          const newOrigins = ['Eastern Europe', 'East Asia', 'North America', 'Unknown'];
          const newSeverities = ['Critical', 'High', 'Medium'];
          
          const randomType = newAttackTypes[Math.floor(Math.random() * newAttackTypes.length)];
          const randomSector = newSectors[Math.floor(Math.random() * newSectors.length)];
          const randomOrigin = newOrigins[Math.floor(Math.random() * newOrigins.length)];
          const randomSeverity = newSeverities[Math.floor(Math.random() * newSeverities.length)];
          
          const now = new Date();
          const formattedDate = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')} ${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
          
          const newAttack = {
            id: Date.now(),
            date: formattedDate,
            type: randomType,
            target: `${randomSector} Sector`,
            severity: randomSeverity,
            origin: randomOrigin,
            status: 'Active'
          };
          
          setAttackData(prevData => {
            const updatedData = [newAttack, ...prevData.slice(0, prevData.length - 1)];
            
            // Show notification for critical threats
            if (randomSeverity === 'Critical') {
              notifyDanger(
                `New ${randomType} Attack Detected`, 
                `A critical ${randomType.toLowerCase()} attack targeting the ${randomSector.toLowerCase()} sector has been detected.`,
                { actionLabel: 'View Details', action: () => console.log('View attack details') }
              );
            }
            
            return updatedData;
          });
        }
      }, 5000);

      return () => clearInterval(interval);
    }, 1500);

    return () => clearTimeout(timer);
  }, [notifyDanger]);

  // Attack statistics for visualization
  const attackTypeStats = {
    'Phishing': 42,
    'DDoS': 27,
    'Ransomware': 18,
    'Data Breach': 13,
    'SQL Injection': 8
  };

  return (
    <div className="dashboard-container">
      <Container fluid className="py-4">
        <h2 className="dashboard-title mb-4">
          <i className="bi bi-shield-lock"></i> Cyber Threat Dashboard
        </h2>

        {/* Top row with summary cards */}
        <Row className="mb-4">
          <Col lg={3} md={6} className="mb-4 mb-lg-0">
            <Card className="threat-card">
              <Card.Body>
                <h4 className="card-title">Current Threat Level</h4>
                <div className="threat-meter">
                  <div className="threat-level" style={{ color: threatLevel > 70 ? '#f43f5e' : threatLevel > 50 ? '#f59e0b' : '#2ea043' }}>
                    {Math.round(threatLevel)}%
                  </div>
                  <ProgressBar className="mt-2" now={threatLevel} variant={threatLevel > 70 ? 'danger' : threatLevel > 50 ? 'warning' : 'success'} />
                </div>
              </Card.Body>
            </Card>
          </Col>
          <Col lg={3} md={6} className="mb-4 mb-lg-0">
            <Card className="threat-card">
              <Card.Body>
                <h4 className="card-title">Active Attacks</h4>
                <div className="threat-count">
                  <div className="count-value">3</div>
                  <div className="count-label">Current incidents</div>
                </div>
              </Card.Body>
            </Card>
          </Col>
          <Col lg={3} md={6} className="mb-4 mb-lg-0">
            <Card className="threat-card">
              <Card.Body>
                <h4 className="card-title">Attack Sources</h4>
                <div className="threat-count">
                  <div className="count-value">7</div>
                  <div className="count-label">Unique origins</div>
                </div>
              </Card.Body>
            </Card>
          </Col>
          <Col lg={3} md={6}>
            <Card className="threat-card">
              <Card.Body>
                <h4 className="card-title">Protected Systems</h4>
                <div className="threat-count">
                  <div className="count-value success-text">156</div>
                  <div className="count-label">Systems secured</div>
                </div>
              </Card.Body>
            </Card>
          </Col>
        </Row>

        {/* Attack trends visualization */}
        <Row className="mb-4">
          <Col lg={8} className="mb-4 mb-lg-0">
            <Card className="chart-card">
              <Card.Header>
                <h4 className="m-0">Attack Distribution</h4>
              </Card.Header>
              <Card.Body>
                <div className="attack-distribution">
                  {Object.entries(attackTypeStats).map(([type, value]) => (
                    <div key={type} className="distribution-item">
                      <div className="d-flex justify-content-between mb-1">
                        <span className="attack-type">{type}</span>
                        <span className="attack-value">{value}%</span>
                      </div>
                      <ProgressBar 
                        now={value} 
                        variant={
                          type === 'Phishing' ? 'primary' : 
                          type === 'DDoS' ? 'danger' : 
                          type === 'Ransomware' ? 'warning' : 
                          type === 'Data Breach' ? 'info' : 
                          'secondary'
                        } 
                        style={{ height: '12px' }}
                      />
                    </div>
                  ))}
                </div>
              </Card.Body>
            </Card>
          </Col>
          <Col lg={4}>
            <Card className="prevention-card">
              <Card.Header>
                <h4 className="m-0">Top Prevention Measures</h4>
              </Card.Header>
              <Card.Body>
                <div className="prevention-list">
                  {preventionMeasures.map(item => (
                    <div key={item.id} className="prevention-item">
                      <div className="d-flex justify-content-between">
                        <h5 className="prevention-threat">{item.threat}</h5>
                        <Badge bg={item.effectiveness > 80 ? 'success' : 'info'}>{item.effectiveness}%</Badge>
                      </div>
                      <p className="prevention-measure">{item.measure}</p>
                      <ProgressBar now={item.effectiveness} variant={item.effectiveness > 80 ? 'success' : 'info'} />
                    </div>
                  ))}
                </div>
              </Card.Body>
            </Card>
          </Col>
        </Row>

        {/* Recent attacks table */}
        <Row className="mb-4">
          <Col>
            <Card className="attacks-card">
              <Card.Header className="d-flex justify-content-between align-items-center">
                <h4 className="m-0">Recent Cyber Attacks</h4>
                <Badge bg="danger" className="pulse-badge">LIVE</Badge>
              </Card.Header>
              <Card.Body className="p-0">
                {isLoading ? (
                  <div className="text-center p-5">
                    <div className="spinner-border text-light" role="status">
                      <span className="visually-hidden">Loading...</span>
                    </div>
                    <p className="mt-3">Fetching attack data...</p>
                  </div>
                ) : (
                  <div className="table-responsive">
                    <Table className="attack-table mb-0">
                      <thead>
                        <tr>
                          <th>Date & Time</th>
                          <th>Attack Type</th>
                          <th>Target Sector</th>
                          <th>Severity</th>
                          <th>Origin</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {attackData.map(attack => (
                          <tr key={attack.id} className={attack.status.toLowerCase() === 'active' ? 'table-danger-subtle' : ''}>
                            <td>{attack.date}</td>
                            <td>{attack.type}</td>
                            <td>{attack.target}</td>
                            <td>
                              <Badge bg={getBadgeVariant(attack.severity)}>{attack.severity}</Badge>
                            </td>
                            <td>{attack.origin}</td>
                            <td>
                              <Badge bg={getStatusBadge(attack.status)}>{attack.status}</Badge>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </Table>
                  </div>
                )}
              </Card.Body>
            </Card>
          </Col>
        </Row>

        {/* Scan History */}
        <Row>
          <Col>
            <Card className="scan-history-card">
              <Card.Header className="d-flex justify-content-between align-items-center">
                <h4 className="m-0">Scan History</h4>
                <Badge bg="info">Recent</Badge>
              </Card.Header>
              <Card.Body className="p-0">
                {isLoading ? (
                  <div className="text-center p-5">
                    <div className="spinner-border text-light" role="status">
                      <span className="visually-hidden">Loading...</span>
                    </div>
                    <p className="mt-3">Fetching scan history...</p>
                  </div>
                ) : (
                  <div className="table-responsive">
                    <Table className="scan-history-table mb-0">
                      <thead>
                        <tr>
                          <th>Date & Time</th>
                          <th>Type</th>
                          <th>Target</th>
                          <th>Result</th>
                          <th>Risk Score</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {scanHistory.map(scan => (
                          <tr key={scan.id} className={scan.result.toLowerCase() === 'phishing' ? 'table-danger-subtle' : ''}>
                            <td>{scan.timestamp}</td>
                            <td>{scan.type}</td>
                            <td className="text-truncate" style={{maxWidth: '300px'}}>{scan.target}</td>
                            <td>
                              <Badge bg={getResultBadge(scan.result)}>{scan.result}</Badge>
                            </td>
                            <td>
                              <div className="d-flex align-items-center">
                                <span className="me-2">{scan.riskScore}%</span>
                                <ProgressBar 
                                  now={scan.riskScore} 
                                  variant={scan.riskScore > 70 ? 'danger' : scan.riskScore > 30 ? 'warning' : 'success'} 
                                  style={{ height: '8px', width: '100px' }} 
                                />
                              </div>
                            </td>
                            <td>
                              <button className="btn btn-sm btn-outline-primary me-2">
                                <i className="bi bi-eye"></i> View
                              </button>
                              <button className="btn btn-sm btn-outline-danger">
                                <i className="bi bi-trash"></i>
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </Table>
                  </div>
                )}
              </Card.Body>
              <Card.Footer className="d-flex justify-content-between align-items-center">
                <span>Showing recent 7 of 124 scans</span>
                <button className="btn btn-sm btn-primary">View All History</button>
              </Card.Footer>
            </Card>
          </Col>
        </Row>
      </Container>
    </div>
  );
};

export default Dashboard; 