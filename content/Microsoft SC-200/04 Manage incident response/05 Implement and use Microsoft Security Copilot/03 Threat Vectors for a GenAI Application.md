
## Core Components of a GenAI Application

1. **AI Data :**
   - Data used across the GenAI lifecycle
   - Includes :
     - Training data
     - Fine-tuning data
     - Operational data

1. **AI Usage :**
   - How users interact with and rely on AI outputs
   - Includes :
     - Decision-making
     - Automation
     - Human–AI collaboration

1. **AI Application :**
   - The application layer wrapping the model
   - Handles :
     - User interaction
     - Prompt handling
     - Integration with external systems

1. **AI Platform :**
   - Infrastructure and services supporting the application
   - Examples :
     - Cloud AI platforms
     - Model hosting services

- Threats can target any of these components

## 1. User → AI Application Threats

### Prompt Injection :
- User submits malicious prompts
- Forces AI to :
  - Ignore safeguards
  - Perform unintended actions
- One of the most common GenAI attacks

### Data Leakage :
- AI exposes sensitive information to users
- Examples :
  - Credentials
  - Internal configuration details
- Results in confidentiality breaches

### Overreliance on AI :
- Users blindly trust AI outputs
- Risks :
  - Incorrect decisions
  - Security failures
  - Business failures
- Considered a human + AI risk
## 2. AI Application ↔ External Systems Threats

### Data Poisoning :
- Attacker manipulates :
  - Training data
  - Fine-tuning data
- Leads to :
  - Biased outputs
  - Incorrect or malicious behavior
- Compromises system integrity

### Supply Chain Risks :
- GenAI applications depend on :
  - Third-party agents
  - Libraries
  - Data sources
  - Cloud platforms (e.g., Azure AI)
- Compromise of any dependency can impact the entire system
## 3. AI Application ↔ Model Threats

### Insecure Plugins :
- Plugins extend model capabilities
- If poorly configured :
  - Can be exploited
  - Can be used to attack the GenAI application
- Example :
  - Copilot plugins (e.g., Defender XDR plugin)

### Jailbreak Attacks :
- Attacker bypasses model safeguards
- Forces the model to :
  - Ignore safety rules
  - Generate restricted or harmful content
## 4. Model ↔ Data Threats

### Model Theft :
- Attacker steals :
  - The underlying model
  - Model parameters or weights

### Model Vulnerabilities :
- Exploitable weaknesses in the model itself
- Can lead to :
  - Unauthorized access
  - System compromise

- ![[Pasted image 20260127171922.png]]

---
