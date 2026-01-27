## Architecture of an LLM

 1. **Users :**
	- Users interact with the **LLM via prompts**
    - Prompts are the main way to ask questions or give instructions

 2. **Application Services (LLM Application Layer) :**
	- First layer that receives user prompts
    - Handles :    
	    - Prompt processing
        - Input/output handling
	    - Communication with other LLM components
    - Everything here is part of the **LLM application**

3. **Automation Agents & Model Interaction :**
	- Application services communicate with :
		- **Automation agents**
        - **The LLM model itself**
        
	- Purpose :    
	    - Route prompts        
	    - Process responses        
	    - Ensure smooth interaction between user and model

4. **Model + Training & Fine-Tuning Data :**
- The model uses :    
    - **Training data**        
    - **Fine-tuning data**
- Example :    
    - Question: _“What is a famous bird species?”_        
    - Model checks learned data to determine what is “famous”

3. **External Data Sources :**
- Data used to :    
    - Train models        
    - Fine-tune models

- Can be :    
    - Online (e.g., internet access)        
    - Offline datasets
	- Not always live internet access

3. **Plugins :**
- Act as **interfaces** between the LLM and other systems    
- Allow LLMs to interact with :    
    - Databases        
    - Websites        
    - Other applications        
- Example :    
    - Plugin connects LLM to a database of famous bird species

3. **Downstream Services :**
- Traditional IT systems :    
    - Databases (e.g., SQL)        
    - Web servers (e.g., Apache)        
    - APIs        
- Not AI-specific
- Plugins simply connect LLMs to these services

- ![[Pasted image 20260127164044.png]]

# Security Perspective (OWASP LLM Top 10)

- **Every layer is attackable**    
- OWASP LLM Top 10 targets :    
    - User inputs        
    - Application services        
    - Model        
    - Plugins        
    - Downstream services
- Downstream services still require **traditional application security**

> **In Simple :**
> 	- LLM architecture = **multiple layers**
> 	- Plugins = **bridge between LLM and external systems**    
	- OWASP threats apply to **all layers**, not just the model    
		- LLM security builds on **traditional IT security principles**

---
