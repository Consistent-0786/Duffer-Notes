# PCI-DSS (Payment Card Industry Data Security Standard)

- **PCI-DSS** is a **security standard** designed to protect **credit card and debit card data**.
- It applies to any organization that **stores, processes, or transmits cardholder data**.
- In Simple:
    - A **security standard that protects credit card information during payment transactions**.

---

# Important PCI-DSS Terms

### CDE (Cardholder Data Environment)

- The **systems, people, and processes** that store, process, or transmit cardholder data.

---

### Merchant

- Any organization that **accepts credit card payments** for goods or services.

Example:

- Online stores
- Retail shops
- Restaurants

---

### PAN (Primary Account Number)

- The **credit/debit card number** used to identify the cardholder account.

---

### Cardholder Data

Minimum required data:

- Full **PAN**

May also include:

- Cardholder name
- Expiration date
- Service code

---

### Sensitive Authentication Data (SAD)

Security data used to **verify card transactions**.

Examples:

- CVV / CVC code
- PIN numbers
- Full magnetic stripe data

This data **must not be stored after authorization**.

---

# PCI-DSS Main Security Goal

Protect **payment card information** by securing:

- Payment systems
- Networks
- Databases
- Applications

---

# Example PCI-DSS Requirement

Example requirement:

**Install and maintain network security controls** to protect cardholder data systems.

---

# High-Level Steps to PCI Compliance

1. Determine the **scope of the Cardholder Data Environment (CDE)**
2. Complete a **Self-Assessment Questionnaire (SAQ)** or security audit
3. **Fix security weaknesses** found in the assessment
4. Submit compliance documentation to the **bank or payment provider**
5. Perform **regular security assessments** to maintain compliance

---

# Security Assessors

### ISA (Internal Security Assessor)

- An **internal employee** trained to perform PCI compliance assessments.

### QSA (Qualified Security Assessor)

- An **external certified auditor** approved by the PCI Security Standards Council.

---

# PCI-DSS Penalties

Failure to comply with PCI-DSS can lead to:

- Large **financial penalties**
- Loss of ability to **process credit card payments**
- Legal consequences

Example:

A major retailer breach exposed **40 million credit card numbers**, leading to **billions in potential liability**.

---

# PCI-DSS Summary

- PCI-DSS protects **credit card data**.
- Applies to organizations handling **payment card transactions**.
- Focuses on **secure systems, networks, and data protection**.

Goal:

Protect **cardholder data and prevent financial fraud**.