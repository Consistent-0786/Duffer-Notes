# Plugins

- Plugins = **interfaces between Copilot and other tools/services**
- Enable Copilot to **interact with external data and services**    
- Provide **real-time analysis, intelligence, and automation**    
- Extend **security use cases** beyond Microsoft products
## Types of plugins :
    
1. **Microsoft-managed*
    - Examples:            
           - Sentinel → SIEM integration                
           - Defender XDR → Endpoint, identity, Office protection                
           - Azure AI Search                
           - Defender External Attack Surface Management → external asset view                
           - Defender Threat Intelligence → threat actor TTPs                
           - Entra → Identity management                
           - Intune → Device management                
           - Purview → Compliance, DLP, insider threats                
           - KQL plugins → query functionality for Defender XDR & Sentinel                
     
2. **Third-party**
        
    - Examples:            
           - Shodan → asset scanning                
           - URLScan → threat intelligence                
           - CrowdSec, Red Canary, CircleHash lookup, CDI, EMF                
    - Can integrate freely available or commercial services      
    
3. **Custom**
        
    - Built via APIs, GPT, or KQL            
    - Can leverage **connectors** (e.g., Azure Logic Apps)

---
