package dtapac.finding

# Default: return empty {} if no match (dtapac sees this as "no decision")
default analysis = {}

# Debug: return the entire input for inspection
debug_input = input

analysis = {
    "state": "NOT_AFFECTED",
    "justification": "PROTECTED_BY_COMPILER",
    "details": "This finding can be captured by normal testing, has not be observed in testing.",
    "comment": "No action necessary",
    "suppress": true
} if {
    input.project.name in ["APEX Control Panel", "Pinnacle Control Panel"]
    input.vulnerability.vulnId == "CVE-2007-3205"
} else = {
    "state": "NOT_AFFECTED",
    "justification": "REQUIRES_ENVIRONMENT",
    "details": "APEX ControlPanel 64 bit CPU architecture not impacted",
    "comment": "Not applicable",
    "suppress": true
} if {
    input.project.name == "APEX Control Panel"
    input.vulnerability.vulnId == "CVE-2024-11236"
} else = {
    "state": "NOT_AFFECTED",
    "justification": "PROTECTED_AT_PERIMETER",
    "details": "Customer configuration required to enable an insecure internet.",
    "comment": "Not applicable",
    "suppress": true
} if {
    input.project.name == "APEX Control Panel"
    input.vulnerability.vulnId == "CVE-2024-11234"
}
