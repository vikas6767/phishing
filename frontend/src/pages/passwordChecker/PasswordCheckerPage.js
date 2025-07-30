import React from 'react';
import { Container, Row, Col, Card } from 'react-bootstrap';
import PasswordChecker from '../../components/passwordChecker/PasswordChecker';
import './PasswordCheckerPage.css';

const PasswordCheckerPage = () => {
  return (
    <div className="password-checker-page">
      <Container fluid className="py-4">
        <Row className="mb-4">
          <Col>
            <h2 className="page-title">
              <i className="bi bi-shield-lock"></i> Password Security Center
            </h2>
            <p className="page-description">
              Check the strength of your passwords and learn how to create more secure ones.
              Strong passwords are an essential part of your online security.
            </p>
          </Col>
        </Row>
        
        <Row>
          <Col lg={7} className="mb-4">
            <PasswordChecker />
          </Col>
          <Col lg={5}>
            <Card className="security-tips-card">
              <Card.Header>
                <h4 className="m-0">Password Security Tips</h4>
              </Card.Header>
              <Card.Body>
                <div className="security-tips">
                  <div className="security-tip">
                    <h5><i className="bi bi-shield-check me-2"></i>Create Strong Passwords</h5>
                    <p>A strong password should be at least 12 characters long, include uppercase and lowercase letters, numbers, and special characters. Avoid using personal information like birthdates or names.</p>
                  </div>
                  
                  <div className="security-tip">
                    <h5><i className="bi bi-grid-3x3 me-2"></i>Use Different Passwords</h5>
                    <p>Avoid using the same password for multiple accounts. If one account is compromised, attackers will try the same credentials on other platforms.</p>
                  </div>
                  
                  <div className="security-tip">
                    <h5><i className="bi bi-key me-2"></i>Consider a Password Manager</h5>
                    <p>Password managers can generate and store strong, unique passwords for all your accounts, so you only need to remember one master password.</p>
                  </div>
                  
                  <div className="security-tip">
                    <h5><i className="bi bi-phone me-2"></i>Enable Two-Factor Authentication</h5>
                    <p>Whenever possible, enable two-factor authentication for an added layer of security beyond just your password.</p>
                  </div>
                  
                  <div className="security-tip">
                    <h5><i className="bi bi-clock-history me-2"></i>Regularly Update Passwords</h5>
                    <p>Change your passwords regularly, especially for critical accounts like email, banking, and social media.</p>
                  </div>
                </div>
                
                <div className="passphrase-example mt-4">
                  <h5>Try using a passphrase:</h5>
                  <div className="example-card">
                    <p className="mb-1"><strong>Instead of:</strong> P@ssw0rd123</p>
                    <p className="mb-0"><strong>Consider:</strong> Purple-Horse-Battery-Staple-42!</p>
                  </div>
                  <p className="small mt-2">Passphrases are longer but easier to remember and typically more secure.</p>
                </div>
              </Card.Body>
              <Card.Footer>
                <a href="#" className="btn btn-sm btn-outline-primary">Learn More About Password Security</a>
              </Card.Footer>
            </Card>
          </Col>
        </Row>
      </Container>
    </div>
  );
};

export default PasswordCheckerPage; 