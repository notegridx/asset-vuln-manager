## asset-vuln-manager (AVM)

A transparent alternative to traditional vulnerability management tools.

AVM is a lightweight vulnerability management application designed for environments where full-scale commercial solutions are not feasible, as well as for learning and experimentation.

It provides a local, inspectable workflow for asset inventory, vulnerability correlation, and alert generation — without relying on opaque matching logic.

---

## Highlights

* Asset and software inventory management  
* Canonical vendor/product linking based on CPE  
* CVE / KEV synchronization  
* Alert generation and operational dashboards  
* CSV / JSON import  
* Alias seed export / import  

---

## Who is this for?

AVM is designed for:

* Small teams without dedicated vulnerability management tooling  
* Environments where a quick, local vulnerability database is needed  
* Security practitioners who want to understand how matching actually works  
* Learning, research, and experimentation with CVE/CPE data  

---

## Quick Start

### Requirements
* Java 21  
* MySQL (recommended)  

### Run

```bash
java -jar asset-vuln-manager-0.1.0.jar \
  --spring.datasource.url="jdbc:mysql://localhost:3306/avm" \
  --spring.datasource.username="avm" \
  --spring.datasource.password="your-password" \
  --app.security.bootstrap-admin.enabled=true \
  --app.security.bootstrap-admin.password="your-admin-password"
```

---

## Getting Started

See the documentation for setup and usage:  
https://avm.notegridx.dev/

You can also try the live demo:  
https://avm-demo.notegridx.dev/

---

## Philosophy

AVM emphasizes **transparency over black-box automation**.

* Canonical linking is explainable  
* Matching logic is visible and traceable  
* Data can be inspected, exported, and reused  

---

## Notes

* This is the first public release (0.1.0)  
* APIs and data model may evolve in future versions  
* Not intended as a full replacement for enterprise-grade solutions  
* Do not expose AVM directly to the internet without proper access control  

---

## License

See the LICENSE file in this repository.
