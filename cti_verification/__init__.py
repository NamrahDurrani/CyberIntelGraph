"""CyberIntelGraph verification and fresh-information layer (Milestone 14).

Plugs into the Milestone 13 agent through cti_agent.hooks:
  * fresh lookup  - live CISA KEV and NVD checks for the CVEs in a question
  * verification  - claim-by-claim check of the written answer against its evidence
"""

__version__ = "0.14.0"
