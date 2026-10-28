# Security policy and responsible use

VulnAssess is intended for authorized defensive assessments only. The default scope is loopback. Configure only assets for which you have permission. No exploit, credential attack, stealth feature, denial-of-service check, or crawler is included.

Do not bind the development server to a public interface. Use a strong secret, maintain Nmap and dependencies, protect the local database, and keep `.env` out of version control. Findings are automated observations and must be validated by a human.

Report suspected security defects privately to the project maintainer with reproducible details. Do not include secrets or data from systems assessed without authorization.
