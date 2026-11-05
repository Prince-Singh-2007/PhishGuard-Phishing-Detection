# Project Report: PhishGuard

## 1. Abstract
PhishGuard is a local educational application that demonstrates how common phishing indicators can be identified in email text and URLs. It provides an explainable risk level and practical safety guidance.

## 2. Problem Statement
Phishing messages often use urgency, impersonation, credential requests and deceptive links to persuade recipients to disclose sensitive information. Users need a simple way to learn and recognise these warning signs.

## 3. Objectives
- Identify suspicious language in sample email text.
- Highlight basic structural warning signs in URLs.
- Explain why an item was flagged.
- Promote safe verification behaviour.
- Demonstrate secure, ethical project development without collecting credentials.

## 4. System Design
User input → Flask web interface → email/URL heuristic detector → risk score and findings → safety recommendation.

## 5. Methodology
The email analyser checks for urgency, credential-related terms, payment-related terms and embedded URLs. The URL analyser checks protocol, hostname shape, URL shorteners, IP-address hosts and other basic structural indicators. Findings are converted into an illustrative score from 0 to 10.

## 6. Tools and Technologies
Python, Flask, HTML, CSS, regular expressions, `urllib.parse`, and `unittest`.

## 7. Testing
The included unit tests verify that urgent credential-related email text is not classified as low risk, that an HTTP URL is flagged, and that empty URL input receives guidance. Run the tests using `python -m unittest discover -s tests -v`.

## 8. Results
The application displays a Low, Medium or High heuristic risk label, a score, a list of detected indicators and a recommended action. Actual results depend on the text supplied.

## 9. Limitations and Future Scope
Future improvements could include a labelled dataset, machine-learning classification, raw email-header analysis, domain reputation checks, multilingual keyword support and a larger test suite. Any external reputation integration should use safe, privacy-aware services and avoid opening suspicious links automatically.

## 10. Conclusion
PhishGuard demonstrates foundational phishing-awareness and defensive analysis concepts in a safe local environment. It is intended for learning and should not be treated as a definitive security verdict.
