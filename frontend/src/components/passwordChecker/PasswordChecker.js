import React, { useState, useEffect } from 'react';
import { Card, Form, Button, ProgressBar, ListGroup } from 'react-bootstrap';
import './PasswordChecker.css';

const PasswordChecker = () => {
  const [password, setPassword] = useState('');
  const [score, setScore] = useState(0);
  const [feedback, setFeedback] = useState([]);

  // Calculate password strength
  useEffect(() => {
    if (!password) {
      setScore(0);
      setFeedback([]);
      return;
    }

    let currentScore = 0;
    const newFeedback = [];

    // Check length
    if (password.length < 8) {
      newFeedback.push({ type: 'danger', message: 'Password is too short (minimum 8 characters)' });
    } else if (password.length >= 12) {
      currentScore += 25;
      newFeedback.push({ type: 'success', message: 'Good password length' });
    } else {
      currentScore += 15;
      newFeedback.push({ type: 'warning', message: 'Consider a longer password (12+ characters ideal)' });
    }

    // Check for numbers
    if (/\d/.test(password)) {
      currentScore += 15;
      newFeedback.push({ type: 'success', message: 'Contains numbers' });
    } else {
      newFeedback.push({ type: 'danger', message: 'Add numbers to strengthen your password' });
    }

    // Check for lowercase
    if (/[a-z]/.test(password)) {
      currentScore += 10;
      newFeedback.push({ type: 'success', message: 'Contains lowercase letters' });
    } else {
      newFeedback.push({ type: 'danger', message: 'Add lowercase letters' });
    }

    // Check for uppercase
    if (/[A-Z]/.test(password)) {
      currentScore += 15;
      newFeedback.push({ type: 'success', message: 'Contains uppercase letters' });
    } else {
      newFeedback.push({ type: 'danger', message: 'Add uppercase letters' });
    }

    // Check for special characters
    if (/[^A-Za-z0-9]/.test(password)) {
      currentScore += 20;
      newFeedback.push({ type: 'success', message: 'Contains special characters' });
    } else {
      newFeedback.push({ type: 'danger', message: 'Add special characters (!@#$%^&*)' });
    }

    // Check for repeating patterns
    if (/(.)\1{2,}/.test(password)) {
      currentScore -= 10;
      newFeedback.push({ type: 'danger', message: 'Avoid repeating characters (e.g., "aaa", "111")' });
    }

    // Check for sequential patterns
    const sequences = ['abcdef', '123456', 'qwerty'];
    let hasSequence = false;
    
    for (let seq of sequences) {
      for (let i = 0; i < seq.length - 2; i++) {
        const pattern = seq.substring(i, i + 3);
        if (password.toLowerCase().includes(pattern)) {
          hasSequence = true;
          break;
        }
      }
      if (hasSequence) break;
    }
    
    if (hasSequence) {
      currentScore -= 15;
      newFeedback.push({ type: 'danger', message: 'Avoid sequential patterns (abc, 123, qwerty)' });
    }

    // Common passwords check
    const commonPasswords = [
      'password', '123456', 'qwerty', 'admin', 'welcome',
      'password123', 'abc123', 'letmein', '123456789'
    ];
    
    if (commonPasswords.includes(password.toLowerCase())) {
      currentScore = 5;
      newFeedback.push({ type: 'danger', message: 'This is a commonly used password!' });
    }

    // Ensure the score is within bounds
    currentScore = Math.max(0, Math.min(100, currentScore));
    setScore(currentScore);
    setFeedback(newFeedback);
  }, [password]);

  // Get the variant color based on score
  const getVariant = (score) => {
    if (score < 30) return 'danger';
    if (score < 60) return 'warning';
    if (score < 80) return 'info';
    return 'success';
  };

  // Get strength text based on score
  const getStrengthText = (score) => {
    if (score < 30) return 'Very Weak';
    if (score < 60) return 'Weak';
    if (score < 80) return 'Moderate';
    if (score < 95) return 'Strong';
    return 'Very Strong';
  };

  return (
    <Card className="password-checker-card">
      <Card.Header>
        <h4 className="m-0">Password Security Checker</h4>
      </Card.Header>
      <Card.Body>
        <Form>
          <Form.Group className="mb-3">
            <Form.Label>Enter a password to check its strength</Form.Label>
            <Form.Control 
              type="password" 
              placeholder="Enter password" 
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="password-input"
            />
          </Form.Group>
          
          <div className="strength-meter mb-4">
            <div className="d-flex justify-content-between mb-2">
              <span>Strength: {getStrengthText(score)}</span>
              <span>{score}%</span>
            </div>
            <ProgressBar 
              now={score} 
              variant={getVariant(score)} 
              style={{ height: '10px' }}
            />
          </div>

          <h5 className="mb-3">Security Analysis</h5>
          <ListGroup className="feedback-list">
            {feedback.map((item, index) => (
              <ListGroup.Item 
                key={index} 
                variant={item.type}
                className={`feedback-item feedback-${item.type}`}
              >
                <i className={`bi ${item.type === 'success' ? 'bi-check-circle' : 'bi-exclamation-circle'} me-2`}></i>
                {item.message}
              </ListGroup.Item>
            ))}
          </ListGroup>

          {password && score >= 80 && (
            <div className="password-success-message mt-4">
              <i className="bi bi-shield-check me-2"></i>
              This password provides good protection against brute force attacks
            </div>
          )}

          <div className="mt-4">
            <Button variant="primary" className="w-100">
              Check for Data Breaches
            </Button>
            <small className="text-muted mt-2 d-block">
              This will check if your password has appeared in known data breaches
            </small>
          </div>
        </Form>
      </Card.Body>
      <Card.Footer>
        <div className="password-tips">
          <h6><i className="bi bi-lightbulb me-2"></i>Pro Tips:</h6>
          <ul className="small mb-0">
            <li>Use a unique password for each important account</li>
            <li>Consider using a password manager</li>
            <li>Enable two-factor authentication when available</li>
            <li>Change passwords regularly (every 3-6 months)</li>
          </ul>
        </div>
      </Card.Footer>
    </Card>
  );
};

export default PasswordChecker; 