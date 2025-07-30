import re
import base64
import email
from email import policy
from email.parser import Parser
from urllib.parse import urlparse
import json

class EmailHeaderAnalyzer:
    """Analyzes email headers for phishing indicators"""
    
    def __init__(self):
        self.suspicious_indicators = []
        self.authentication_results = {}
        self.routing_info = []
        self.parsed_headers = {}
    
    def analyze(self, headers_text):
        """Main analysis function for email headers
        
        Args:
            headers_text (str): Raw email headers as text
            
        Returns:
            dict: Analysis results with risk assessment
        """
        self.suspicious_indicators = []
        self.authentication_results = {}
        self.routing_info = []
        
        # Parse the headers
        headers = Parser(policy=policy.default).parsestr(headers_text)
        
        # Extract key headers
        self.parsed_headers = {
            'from': headers.get('From', ''),
            'to': headers.get('To', ''),
            'subject': headers.get('Subject', ''),
            'date': headers.get('Date', ''),
            'message_id': headers.get('Message-ID', ''),
            'reply_to': headers.get('Reply-To', ''),
            'return_path': headers.get('Return-Path', ''),
            'received': self._parse_received_headers(headers),
            'authentication_results': headers.get('Authentication-Results', ''),
            'dkim_signature': headers.get('DKIM-Signature', ''),
            'spf': '',
            'dkim': '',
            'dmarc': ''
        }
        
        # Check for authentication results
        self._parse_authentication_results()
        
        # Check for indicators of phishing
        self._check_spoofing_indicators()
        self._check_unusual_routing()
        self._check_reply_to_mismatch()
        
        # Calculate risk score (0-100)
        risk_score = self._calculate_risk_score()
        
        return {
            'parsed_headers': self.parsed_headers,
            'authentication_results': self.authentication_results,
            'suspicious_indicators': self.suspicious_indicators,
            'routing_info': self.routing_info,
            'risk_score': risk_score,
            'risk_level': self._risk_level_from_score(risk_score)
        }
    
    def _parse_received_headers(self, headers):
        """Extract and parse Received headers"""
        received_headers = headers.get_all('Received', [])
        return received_headers
    
    def _parse_authentication_results(self):
        """Parse SPF, DKIM, and DMARC results from headers"""
        auth_results = self.parsed_headers['authentication_results']
        
        # Parse SPF
        spf_match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
        if spf_match:
            self.authentication_results['spf'] = spf_match.group(1).lower()
            self.parsed_headers['spf'] = spf_match.group(1).lower()
        
        # Parse DKIM
        dkim_match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
        if dkim_match:
            self.authentication_results['dkim'] = dkim_match.group(1).lower()
            self.parsed_headers['dkim'] = dkim_match.group(1).lower()
        
        # Parse DMARC
        dmarc_match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
        if dmarc_match:
            self.authentication_results['dmarc'] = dmarc_match.group(1).lower()
            self.parsed_headers['dmarc'] = dmarc_match.group(1).lower()
    
    def _check_spoofing_indicators(self):
        """Check for indicators of email spoofing"""
        
        # Check SPF
        if 'spf' in self.authentication_results:
            if self.authentication_results['spf'] != 'pass':
                self.suspicious_indicators.append({
                    'type': 'authentication',
                    'name': 'SPF Authentication Failure',
                    'description': 'Email failed SPF authentication, suggesting possible spoofing',
                    'severity': 'high'
                })
        else:
            self.suspicious_indicators.append({
                'type': 'authentication',
                'name': 'Missing SPF Authentication',
                'description': 'No SPF authentication results found',
                'severity': 'medium'
            })
        
        # Check DKIM
        if 'dkim' in self.authentication_results:
            if self.authentication_results['dkim'] != 'pass':
                self.suspicious_indicators.append({
                    'type': 'authentication',
                    'name': 'DKIM Authentication Failure',
                    'description': 'Email failed DKIM authentication, suggesting tampering',
                    'severity': 'high'
                })
        else:
            self.suspicious_indicators.append({
                'type': 'authentication',
                'name': 'Missing DKIM Authentication',
                'description': 'No DKIM authentication results found',
                'severity': 'medium'
            })
        
        # Check DMARC
        if 'dmarc' in self.authentication_results:
            if self.authentication_results['dmarc'] != 'pass':
                self.suspicious_indicators.append({
                    'type': 'authentication',
                    'name': 'DMARC Authentication Failure',
                    'description': 'Email failed DMARC authentication',
                    'severity': 'high'
                })
        else:
            self.suspicious_indicators.append({
                'type': 'authentication',
                'name': 'Missing DMARC Authentication',
                'description': 'No DMARC authentication results found',
                'severity': 'low'
            })
    
    def _check_unusual_routing(self):
        """Check for unusual email routing patterns"""
        received_headers = self.parsed_headers['received']
        
        # Extract IP addresses from Received headers
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        for i, header in enumerate(received_headers):
            ips = re.findall(ip_pattern, header)
            
            # Add to routing info
            if ips:
                self.routing_info.append({
                    'hop': i + 1,
                    'header': header,
                    'ip_addresses': ips
                })
                
        # Check for excessive hops
        if len(received_headers) > 15:
            self.suspicious_indicators.append({
                'type': 'routing',
                'name': 'Excessive Mail Hops',
                'description': f'Email passed through {len(received_headers)} servers, which is unusual',
                'severity': 'medium'
            })
    
    def _check_reply_to_mismatch(self):
        """Check if Reply-To doesn't match From header"""
        from_email = self._extract_email(self.parsed_headers['from'])
        reply_to = self._extract_email(self.parsed_headers['reply_to'])
        return_path = self._extract_email(self.parsed_headers['return_path'])
        
        if reply_to and from_email and reply_to != from_email:
            self.suspicious_indicators.append({
                'type': 'mismatch',
                'name': 'Reply-To/From Mismatch',
                'description': f'Reply-To address ({reply_to}) differs from From address ({from_email})',
                'severity': 'high'
            })
        
        if return_path and from_email and return_path != from_email:
            self.suspicious_indicators.append({
                'type': 'mismatch',
                'name': 'Return-Path/From Mismatch',
                'description': f'Return-Path ({return_path}) differs from From address ({from_email})',
                'severity': 'medium'
            })
    
    def _extract_email(self, header_value):
        """Extract email address from a header value"""
        if not header_value:
            return ''
            
        # Try to match email pattern
        email_pattern = r'[\w\.-]+@[\w\.-]+'
        match = re.search(email_pattern, header_value)
        
        if match:
            return match.group(0).lower()
        
        return header_value.lower()
    
    def _calculate_risk_score(self):
        """Calculate a risk score based on findings"""
        score = 0
        
        # Authentication failures have high weight
        if 'spf' in self.authentication_results and self.authentication_results['spf'] != 'pass':
            score += 25
        
        if 'dkim' in self.authentication_results and self.authentication_results['dkim'] != 'pass':
            score += 25
            
        if 'dmarc' in self.authentication_results and self.authentication_results['dmarc'] != 'pass':
            score += 15
        
        # Missing authentications
        if 'spf' not in self.authentication_results:
            score += 10
        
        if 'dkim' not in self.authentication_results:
            score += 10
            
        if 'dmarc' not in self.authentication_results:
            score += 5
        
        # Each other suspicious indicator
        for indicator in self.suspicious_indicators:
            if indicator['type'] not in ['authentication']:  # Already counted above
                if indicator['severity'] == 'high':
                    score += 15
                elif indicator['severity'] == 'medium':
                    score += 10
                else:
                    score += 5
        
        # Cap at 100
        return min(score, 100)
    
    def _risk_level_from_score(self, score):
        """Convert numerical score to risk level"""
        if score >= 75:
            return 'High Risk'
        elif score >= 40:
            return 'Medium Risk'
        elif score >= 15:
            return 'Low Risk'
        else:
            return 'Safe'


class EmailContentAnalyzer:
    """Analyzes email content for phishing indicators"""
    
    def __init__(self):
        self.suspicious_indicators = []
        self.extracted_urls = []
        self.social_engineering_tactics = []
    
    def analyze(self, sender, subject, body):
        """Main analysis function for email content
        
        Args:
            sender (str): Sender email address
            subject (str): Email subject line
            body (str): Email body content
            
        Returns:
            dict: Analysis results with risk assessment
        """
        self.suspicious_indicators = []
        self.extracted_urls = []
        self.social_engineering_tactics = []
        
        # Analyze sender domain
        self._analyze_sender(sender)
        
        # Analyze subject line
        self._analyze_subject(subject)
        
        # Analyze email body
        self._analyze_body(body)
        
        # Extract and analyze URLs
        self._extract_urls(body)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score()
        
        return {
            'suspicious_indicators': self.suspicious_indicators,
            'extracted_urls': self.extracted_urls,
            'social_engineering_tactics': self.social_engineering_tactics,
            'risk_score': risk_score,
            'risk_level': self._risk_level_from_score(risk_score)
        }
    
    def _analyze_sender(self, sender):
        """Analyze sender email address for suspicious patterns"""
        if not sender:
            return
            
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.pw', '.cf', '.ga', '.gq', '.ml', '.buzz', '.xyz', '.top']
        for tld in suspicious_tlds:
            if sender.lower().endswith(tld):
                self.suspicious_indicators.append({
                    'type': 'sender',
                    'name': 'Suspicious Email TLD',
                    'description': f'Sender uses suspicious top-level domain: {tld}',
                    'severity': 'medium'
                })
                break
        
        # Check for random-looking or unusual sender names
        sender_parts = sender.split('@')
        if len(sender_parts) > 1:
            local_part = sender_parts[0]
            
            # Random-looking patterns with numbers and letters
            if re.match(r'^[a-z0-9]{10,}$', local_part, re.IGNORECASE):
                self.suspicious_indicators.append({
                    'type': 'sender',
                    'name': 'Suspicious Sender Username',
                    'description': 'Sender username appears random or machine-generated',
                    'severity': 'low'
                })
            
            # Check for lookalike domains
            if len(sender_parts) > 1:
                domain = sender_parts[1].lower()
                
                # Check for common lookalike domains
                known_brands = {
                    'google': ['goggle', 'g00gle', 'gooogle'],
                    'microsoft': ['microsft', 'micr0soft', 'micro-soft'],
                    'amazon': ['amaz0n', 'amazn', 'amzon'],
                    'paypal': ['paypa1', 'paypall', 'pay-pal'],
                    'facebook': ['faceb00k', 'facbook', 'face-book'],
                    'apple': ['appl', 'app1e', 'ap-ple']
                }
                
                for brand, lookalikes in known_brands.items():
                    if any(lookalike in domain and brand not in domain for lookalike in lookalikes):
                        self.suspicious_indicators.append({
                            'type': 'sender',
                            'name': 'Lookalike Domain',
                            'description': f'Sender domain may be impersonating {brand}',
                            'severity': 'high'
                        })
                        break
    
    def _analyze_subject(self, subject):
        """Analyze email subject for phishing indicators"""
        if not subject:
            return
            
        subject = subject.lower()
        
        # Check for urgent language
        urgent_terms = ['urgent', 'immediate', 'attention', 'important', 'alert', 
                       'action required', 'warning', 'critical', 'suspended']
        
        for term in urgent_terms:
            if term in subject:
                self.suspicious_indicators.append({
                    'type': 'subject',
                    'name': 'Urgency in Subject',
                    'description': f'Subject contains urgent language: "{term}"',
                    'severity': 'medium'
                })
                self.social_engineering_tactics.append('urgency')
                break
        
        # Check for financial terms
        financial_terms = ['account', 'payment', 'invoice', 'transaction', 'bank', 
                          'credit card', 'paypal', 'deposit', 'tax', 'refund', 'billing']
        
        for term in financial_terms:
            if term in subject:
                self.suspicious_indicators.append({
                    'type': 'subject',
                    'name': 'Financial Terms in Subject',
                    'description': f'Subject contains financial terms: "{term}"',
                    'severity': 'low'
                })
                break
        
        # Check for excessive punctuation or capitalization
        if re.search(r'[!?]{2,}', subject) or re.search(r'[A-Z]{5,}', subject):
            self.suspicious_indicators.append({
                'type': 'subject',
                'name': 'Unusual Formatting',
                'description': 'Subject contains excessive punctuation or capitalization',
                'severity': 'low'
            })
    
    def _analyze_body(self, body):
        """Analyze email body for phishing indicators"""
        if not body:
            return
            
        body_lower = body.lower()
        
        # Check for phishing phrases
        phishing_phrases = [
            'verify your account', 'confirm your account', 'update your information',
            'update your password', 'login to your account', 'suspicious activity',
            'click here to verify', 'security alert', 'limited time', 'act now',
            'failure to comply', 'your account has been suspended', 'unauthorized access'
        ]
        
        for phrase in phishing_phrases:
            if phrase in body_lower:
                self.suspicious_indicators.append({
                    'type': 'body',
                    'name': 'Phishing Phrase Detected',
                    'description': f'Email contains suspicious phrase: "{phrase}"',
                    'severity': 'medium'
                })
                break
        
        # Check for urgency/threat tactics
        urgency_phrases = [
            'immediate action', 'urgent action', 'time sensitive', 'expires soon',
            'final notice', 'last chance', 'deadline', 'suspended', 'terminated',
            'locked', 'disabled', 'deleted', 'criminal', 'illegal', 'unauthorized'
        ]
        
        for phrase in urgency_phrases:
            if phrase in body_lower:
                if 'urgency' not in self.social_engineering_tactics:
                    self.social_engineering_tactics.append('urgency')
                self.suspicious_indicators.append({
                    'type': 'body',
                    'name': 'Urgency or Threat Tactic',
                    'description': f'Email uses urgency or threat: "{phrase}"',
                    'severity': 'medium'
                })
                break
        
        # Check for poor grammar and spelling (simple check)
        common_errors = [
            'detecte unusual', 'suspicius', 'kindely', 'inconvinience', 'securty',
            'verifcation', 'informations', 'we detected', 'we notice', 'we noticed unusual', 
            'need update'
        ]
        
        for error in common_errors:
            if error in body_lower:
                self.suspicious_indicators.append({
                    'type': 'body',
                    'name': 'Grammar/Spelling Errors',
                    'description': 'Email contains grammatical or spelling errors',
                    'severity': 'low'
                })
                break
        
        # Check for reward/fear tactics
        reward_phrases = ['free', 'bonus', 'prize', 'winner', 'discount', 'offer', 'gift', 'reward']
        fear_phrases = ['breach', 'hacked', 'vulnerable', 'at risk', 'compromised', 'stolen', 'fraud']
        
        for phrase in reward_phrases:
            if phrase in body_lower:
                self.social_engineering_tactics.append('reward')
                break
                
        for phrase in fear_phrases:
            if phrase in body_lower:
                self.social_engineering_tactics.append('fear')
                break
    
    def _extract_urls(self, body):
        """Extract and analyze URLs from email body"""
        if not body:
            return
            
        # Simple URL extraction pattern
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}'
        found_urls = re.findall(url_pattern, body)
        
        suspicious_tlds = ['.tk', '.pw', '.cf', '.ga', '.gq', '.ml', '.buzz', '.xyz', '.top']
        
        # Track URL mismatches (text vs href)
        link_text_pattern = r'<a\s+(?:[^>]*?\s+)?href=(["\'])(.*?)\1[^>]*>(.*?)</a>'
        link_text_matches = re.findall(link_text_pattern, body, re.IGNORECASE | re.DOTALL)
        
        for url in found_urls:
            url_info = {
                'url': url,
                'suspicious': False,
                'reason': ''
            }
            
            # Ensure URL has a scheme
            if not url.startswith(('http://', 'https://')):
                if url.startswith('www.'):
                    url = 'http://' + url
                else:
                    url = 'http://' + url
            
            try:
                parsed = urlparse(url)
                
                # Check for suspicious TLDs
                for tld in suspicious_tlds:
                    if parsed.netloc.lower().endswith(tld):
                        url_info['suspicious'] = True
                        url_info['reason'] = f'Suspicious TLD: {tld}'
                        
                        self.suspicious_indicators.append({
                            'type': 'url',
                            'name': 'Suspicious URL TLD',
                            'description': f'Email contains URL with suspicious TLD: {tld}',
                            'severity': 'high'
                        })
                        break
                
                # Check for IP addresses in URLs
                if re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', parsed.netloc):
                    url_info['suspicious'] = True
                    url_info['reason'] = 'IP address in URL'
                    
                    self.suspicious_indicators.append({
                        'type': 'url',
                        'name': 'IP Address URL',
                        'description': 'Email contains URL with IP address instead of domain name',
                        'severity': 'high'
                    })
                
                # Check for URL redirects
                if '@' in parsed.netloc:
                    url_info['suspicious'] = True
                    url_info['reason'] = 'URL contains @ symbol (possible redirection)'
                    
                    self.suspicious_indicators.append({
                        'type': 'url',
                        'name': 'URL Redirection',
                        'description': 'URL uses @ symbol for redirection',
                        'severity': 'high'
                    })
                
                # Check for unusual number of subdomains
                subdomain_count = len(parsed.netloc.split('.')) - 2
                if subdomain_count > 3:
                    url_info['suspicious'] = True 
                    url_info['reason'] = f'Unusual number of subdomains ({subdomain_count})'
                    
                    self.suspicious_indicators.append({
                        'type': 'url',
                        'name': 'Excessive Subdomains',
                        'description': f'URL contains {subdomain_count} subdomains',
                        'severity': 'medium'
                    })
                
                self.extracted_urls.append(url_info)
                
            except Exception:
                # Invalid URL, but still track it
                url_info['suspicious'] = True
                url_info['reason'] = 'Invalid URL format'
                self.extracted_urls.append(url_info)
        
        # Look for URL text mismatches
        for href, url, text in link_text_matches:
            if text and url and text.strip() != url.strip() and not text.strip() in url.strip():
                if not any(u['url'] == url and 'URL text mismatch' in u.get('reason', '') for u in self.extracted_urls):
                    mismatch_found = True
                    for u in self.extracted_urls:
                        if u['url'] == url:
                            u['suspicious'] = True
                            u['reason'] += ' URL text mismatch (displays as: ' + text.strip() + ')'
                            mismatch_found = False
                            break
                    
                    if mismatch_found:
                        self.extracted_urls.append({
                            'url': url,
                            'suspicious': True,
                            'reason': 'URL text mismatch (displays as: ' + text.strip() + ')'
                        })
                    
                    self.suspicious_indicators.append({
                        'type': 'url',
                        'name': 'URL Text Mismatch',
                        'description': f'Link text "{text.strip()}" doesn\'t match the actual URL',
                        'severity': 'high'
                    })
    
    def _calculate_risk_score(self):
        """Calculate a risk score based on findings"""
        score = 0
        
        # URL indicators have high weight
        url_indicators = [i for i in self.suspicious_indicators if i['type'] == 'url']
        for indicator in url_indicators:
            if indicator['severity'] == 'high':
                score += 25
            elif indicator['severity'] == 'medium':
                score += 15
            else:
                score += 5
        
        # Body indicators
        body_indicators = [i for i in self.suspicious_indicators if i['type'] == 'body']
        for indicator in body_indicators:
            if indicator['severity'] == 'high':
                score += 20
            elif indicator['severity'] == 'medium':
                score += 10
            else:
                score += 5
        
        # Subject indicators
        subject_indicators = [i for i in self.suspicious_indicators if i['type'] == 'subject']
        for indicator in subject_indicators:
            if indicator['severity'] == 'high':
                score += 15
            elif indicator['severity'] == 'medium':
                score += 10
            else:
                score += 5
        
        # Sender indicators
        sender_indicators = [i for i in self.suspicious_indicators if i['type'] == 'sender']
        for indicator in sender_indicators:
            if indicator['severity'] == 'high':
                score += 15
            elif indicator['severity'] == 'medium':
                score += 10
            else:
                score += 5
        
        # Social engineering tactics
        score += len(self.social_engineering_tactics) * 10
        
        # Cap at 100
        return min(score, 100)
    
    def _risk_level_from_score(self, score):
        """Convert numerical score to risk level"""
        if score >= 75:
            return 'High Risk'
        elif score >= 40:
            return 'Medium Risk'
        elif score >= 15:
            return 'Low Risk'
        else:
            return 'Safe'

# Initialize analyzers
header_analyzer = EmailHeaderAnalyzer()
content_analyzer = EmailContentAnalyzer()

def analyze_email_headers(headers_text):
    """Analyze email headers for phishing indicators
    
    Args:
        headers_text (str): Raw email headers as text
        
    Returns:
        dict: Analysis results with risk assessment
    """
    return header_analyzer.analyze(headers_text)

def analyze_email_content(sender, subject, body):
    """Analyze email content for phishing indicators
    
    Args:
        sender (str): Sender email address
        subject (str): Email subject line
        body (str): Email body content
        
    Returns:
        dict: Analysis results with risk assessment
    """
    return content_analyzer.analyze(sender, subject, body) 