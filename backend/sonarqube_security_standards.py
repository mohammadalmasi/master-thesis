"""
SonarQube Security Standards Implementation
Based on SonarQube's SecurityStandards.java
"""

from enum import Enum
from typing import Set, Dict, List


class VulnerabilityProbability(Enum):
    """Vulnerability probability levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SQCategory(Enum):
    """SonarQube Security Categories"""
    BUFFER_OVERFLOW = "buffer-overflow"
    SQL_INJECTION = "sql-injection"
    COMMAND_INJECTION = "command-injection"
    PATH_TRAVERSAL_INJECTION = "path-traversal-injection"
    LDAP_INJECTION = "ldap-injection"
    XPATH_INJECTION = "xpath-injection"
    RCE = "rce"
    DOS = "dos"
    SSRF = "ssrf"
    CSRF = "csrf"
    XSS = "xss"
    LOG_INJECTION = "log-injection"
    HTTP_RESPONSE_SPLITTING = "http-response-splitting"
    OPEN_REDIRECT = "open-redirect"
    XXE = "xxe"
    OBJECT_INJECTION = "object-injection"
    WEAK_CRYPTOGRAPHY = "weak-cryptography"
    AUTH = "auth"
    INSECURE_CONF = "insecure-conf"
    FILE_MANIPULATION = "file-manipulation"
    ENCRYPTION_OF_SENSITIVE_DATA = "encryption-of-sensitive-data"
    TRACEABILITY = "traceability"
    PERMISSION = "permission"
    OTHERS = "others"

    def getKey(self):
        return self.value


class OwaspTop10(Enum):
    """OWASP Top 10 2017 Categories"""
    A1 = "a1"
    A2 = "a2"
    A3 = "a3"
    A4 = "a4"
    A5 = "a5"
    A6 = "a6"
    A7 = "a7"
    A8 = "a8"
    A9 = "a9"
    A10 = "a10"


class OwaspTop10_2021(Enum):
    """OWASP Top 10 2021 Categories"""
    A1 = "a1"
    A2 = "a2"
    A3 = "a3"
    A4 = "a4"
    A5 = "a5"
    A6 = "a6"
    A7 = "a7"
    A8 = "a8"
    A9 = "a9"
    A10 = "a10"


class SansTop25(Enum):
    """SANS Top 25 Categories"""
    INSECURE_INTERACTION = "insecure-interaction-between-components"
    RISKY_RESOURCE = "risky-resource-management"
    POROUS_DEFENSES = "porous-defenses"


class PciDss(Enum):
    """PCI DSS Categories"""
    R1 = "1"
    R2 = "2"
    R3 = "3"
    R4 = "4"
    R5 = "5"
    R6 = "6"
    R7 = "7"
    R8 = "8"
    R9 = "9"
    R10 = "10"
    R11 = "11"
    R12 = "12"

    def category(self):
        return self.value


class OwaspAsvs(Enum):
    """OWASP ASVS Categories"""
    C1 = "1"
    C2 = "2"
    C3 = "3"
    C4 = "4"
    C5 = "5"
    C6 = "6"
    C7 = "7"
    C8 = "8"
    C9 = "9"
    C10 = "10"
    C11 = "11"
    C12 = "12"
    C13 = "13"
    C14 = "14"

    def category(self):
        return self.value


class SecurityStandards:
    """Security Standards implementation based on SonarQube"""
    
    UNKNOWN_STANDARD = "unknown"
    
    # CWE mappings by SonarQube category
    CWES_BY_SQ_CATEGORY: Dict[SQCategory, Set[str]] = {
        SQCategory.BUFFER_OVERFLOW: {"119", "120", "131", "676", "788"},
        SQCategory.SQL_INJECTION: {"89", "564", "943"},
        SQCategory.COMMAND_INJECTION: {"77", "78", "88", "214"},
        SQCategory.PATH_TRAVERSAL_INJECTION: {"22"},
        SQCategory.LDAP_INJECTION: {"90"},
        SQCategory.XPATH_INJECTION: {"643"},
        SQCategory.RCE: {"94", "95"},
        SQCategory.DOS: {"400", "624"},
        SQCategory.SSRF: {"918"},
        SQCategory.CSRF: {"352"},
        SQCategory.XSS: {"79", "80", "81", "82", "83", "84", "85", "86", "87"},
        SQCategory.LOG_INJECTION: {"117"},
        SQCategory.HTTP_RESPONSE_SPLITTING: {"113"},
        SQCategory.OPEN_REDIRECT: {"601"},
        SQCategory.XXE: {"611", "827"},
        SQCategory.OBJECT_INJECTION: {"134", "470", "502"},
        SQCategory.WEAK_CRYPTOGRAPHY: {"295", "297", "321", "322", "323", "324", "325", "326", "327", "328", "330", "780"},
        SQCategory.AUTH: {"798", "640", "620", "549", "522", "521", "263", "262", "261", "259", "308"},
        SQCategory.INSECURE_CONF: {"102", "277", "346", "614", "732", "798"},
        SQCategory.FILE_MANIPULATION: {"97", "73"},
        SQCategory.ENCRYPTION_OF_SENSITIVE_DATA: {"311", "315", "319"},
        SQCategory.TRACEABILITY: {"778"},
        SQCategory.PERMISSION: {"266", "269", "284", "668", "732"}
    }
    
    # OWASP Top 10 2017 mappings
    OWASP_TOP_10_2017_MAPPINGS: Dict[str, Set[str]] = {
        "a1": {"79", "89", "564", "943", "1321"},
        "a2": {"287", "352", "384", "613", "798"},
        "a3": {"200", "209", "311", "313", "325", "327", "328", "329", "330", "359", "532", "566", "614", "759", "798", "916"},
        "a4": {"22", "23", "35", "36", "77", "78", "79", "88", "89", "90", "91", "564", "601", "611", "643", "827", "943"},
        "a5": {"284", "285", "287", "306", "307", "346", "352", "425", "441", "497", "538", "565", "614", "732", "798", "863", "918"},
        "a6": {"200", "209", "213", "532", "538", "552", "566", "598", "614", "756", "776", "942"},
        "a7": {"79", "89", "116", "117", "134", "352", "470", "502", "564", "611", "643", "827", "943"},
        "a8": {"22", "23", "35", "36", "73", "77", "78", "79", "88", "89", "90", "91", "94", "95", "97", "134", "184", "470", "502", "564", "611", "643", "827", "943"},
        "a9": {"200", "209", "295", "297", "311", "313", "315", "319", "321", "322", "323", "324", "325", "326", "327", "328", "329", "330", "359", "532", "552", "566", "614", "759", "780", "798", "916", "942"},
        "a10": {"200", "209", "213", "532", "538", "552", "566", "598", "614", "756", "776", "942"}
    }
    
    # OWASP Top 10 2021 mappings
    OWASP_TOP_10_2021_MAPPINGS: Dict[str, Set[str]] = {
        "a1": {"284", "285", "287", "306", "307", "346", "352", "425", "441", "497", "538", "565", "614", "732", "798", "863", "918"},
        "a2": {"209", "256", "295", "297", "311", "321", "322", "323", "324", "325", "326", "327", "328", "330", "331", "334", "335", "336", "337", "338", "340", "347", "523", "720", "759", "780", "818", "916"},
        "a3": {"77", "78", "79", "88", "89", "90", "91", "94", "95", "116", "117", "134", "352", "470", "502", "564", "611", "643", "827", "943"},
        "a4": {"22", "23", "35", "36", "73", "77", "78", "79", "88", "89", "90", "91", "94", "95", "97", "134", "184", "470", "502", "564", "611", "643", "827", "943"},
        "a5": {"1", "200", "209", "213", "532", "538", "552", "566", "598", "614", "756", "776", "942"},
        "a6": {"200", "209", "311", "313", "325", "327", "328", "329", "330", "359", "532", "566", "614", "759", "798", "916"},
        "a7": {"200", "209", "213", "532", "538", "552", "566", "598", "614", "756", "776", "942"},
        "a8": {"22", "23", "35", "36", "73", "77", "78", "79", "88", "89", "90", "91", "94", "95", "97", "134", "184", "470", "502", "564", "611", "643", "827", "943"},
        "a9": {"200", "209", "213", "532", "538", "552", "566", "598", "614", "756", "776", "942"},
        "a10": {"352", "918"}
    }
    
    # SANS Top 25 mappings
    CWES_BY_SANS_TOP_25: Dict[str, Set[str]] = {
        SansTop25.INSECURE_INTERACTION.value: {"79", "89", "352", "601", "611", "643", "827", "943"},
        SansTop25.RISKY_RESOURCE.value: {"22", "73", "77", "78", "88", "94", "95", "134", "184", "470", "502"},
        SansTop25.POROUS_DEFENSES.value: {"116", "117", "200", "209", "213", "284", "285", "287", "306", "307", "346", "425", "441", "497", "532", "538", "552", "565", "566", "598", "614", "732", "756", "776", "798", "863", "918", "942"}
    }
    
    # OWASP ASVS 4.0 requirements by level
    OWASP_ASVS_40_LEVEL_1: List[str] = [
        "2.1.1", "2.1.10", "2.1.11", "2.1.12", "2.1.2", "2.1.3", "2.1.4", "2.1.5", "2.1.6", "2.1.7", "2.1.8", "2.1.9",
        "2.10.1", "2.10.2", "2.10.3", "2.10.4", "2.2.1", "2.2.2", "2.2.3", "2.3.1", "2.5.1", "2.5.2", "2.5.3", "2.5.4",
        "2.5.5", "2.5.6", "2.7.1", "2.7.2", "2.7.3", "2.7.4", "2.8.1", "3.1.1", "3.2.1", "3.2.2", "3.2.3", "3.3.1",
        "3.3.2", "3.4.4", "3.4.5", "3.7.1", "4.1.1", "4.1.2", "4.1.3", "4.1.4", "4.1.5", "4.2.1", "4.2.2", "4.3.1",
        "4.3.2", "5.1.1", "5.1.2", "5.1.3", "5.1.4", "5.1.5", "5.2.1", "5.2.2", "5.2.3", "5.2.4", "5.2.5", "5.2.6",
        "5.2.7", "5.2.8", "5.3.1", "5.3.2", "5.3.3", "5.3.4", "5.3.5", "5.3.6", "5.3.7", "5.3.8", "5.3.9", "5.3.10",
        "5.4.1", "5.4.2", "5.4.3", "5.5.1", "5.5.2", "5.5.3", "5.5.4", "7.1.1", "7.1.2", "7.2.1", "7.2.2", "7.4.1",
        "8.2.1", "8.2.2", "8.2.3", "8.3.1", "8.3.2", "8.3.3", "8.3.4", "9.1.1", "9.1.2", "9.1.3", "10.1.1", "10.3.1",
        "10.3.2", "10.3.3", "11.1.1", "11.1.2", "11.1.3", "11.1.4", "11.1.5", "12.1.1", "12.2.1", "12.3.1", "12.3.2",
        "12.3.3", "12.3.4", "12.3.5", "12.4.1", "12.4.2", "12.5.1", "12.5.2", "12.6.1", "13.1.1", "13.1.2", "13.1.3",
        "13.2.1", "13.2.2", "13.2.3", "13.3.1", "13.4.1", "13.4.2", "14.1.1", "14.1.2", "14.1.3", "14.1.4", "14.2.1",
        "14.2.2", "14.2.3", "14.3.1", "14.3.2", "14.3.3", "14.4.1", "14.4.2", "14.4.3", "14.4.4", "14.4.5", "14.4.6",
        "14.4.7", "14.5.1", "14.5.2", "14.5.3"
    ]
    
    OWASP_ASVS_40_LEVEL_2: List[str] = OWASP_ASVS_40_LEVEL_1 + [
        "1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.1.5", "1.1.6", "1.1.7", "1.10.1", "1.11.1", "1.11.2", "1.12.1",
        "1.12.2", "1.14.1", "1.14.2", "1.14.3", "1.14.4", "1.14.5", "1.14.6", "1.2.1", "1.2.2", "1.2.3", "1.2.4",
        "1.4.1", "1.4.2", "1.4.3", "1.4.4", "1.4.5", "1.5.1", "1.5.2", "1.5.3", "1.5.4", "1.6.1", "1.6.2", "1.6.3",
        "1.6.4", "1.7.1", "1.7.2", "1.8.1", "1.8.2", "1.9.1", "1.9.2", "2.3.2", "2.3.3", "2.4.1", "2.4.2", "2.4.3",
        "2.4.4", "2.4.5", "2.5.7", "2.6.1", "2.6.2", "2.6.3", "2.7.5", "2.7.6", "2.8.2", "2.8.3", "2.8.4", "2.8.5",
        "2.8.6", "2.9.1", "2.9.2", "2.9.3", "3.2.4", "3.3.3", "3.3.4", "3.5.1", "3.5.2", "3.5.3", "4.3.3", "5.4.1",
        "5.4.2", "5.4.3", "6.1.1", "6.1.2", "6.1.3", "6.2.2", "6.2.3", "6.2.4", "6.2.5", "6.2.6", "6.3.1", "6.3.2",
        "6.4.1", "6.4.2", "7.1.3", "7.1.4", "7.2.1", "7.2.2", "7.3.1", "7.3.2", "7.3.3", "7.3.4", "7.4.2", "7.4.3",
        "8.1.1", "8.1.2", "8.1.3", "8.1.4", "8.3.5", "8.3.6", "8.3.7", "8.3.8", "9.2.1", "9.2.2", "9.2.3", "9.2.4",
        "10.2.1", "10.2.2", "11.1.6", "11.1.7", "11.1.8", "12.1.2", "12.1.3", "12.2.1", "12.3.6", "13.1.4", "13.1.5",
        "13.2.4", "13.2.5", "13.2.6", "13.3.2", "13.4.1", "13.4.2", "14.1.1", "14.1.2", "14.1.3", "14.1.4", "14.2.4",
        "14.2.5", "14.2.6", "14.5.4"
    ]
    
    OWASP_ASVS_40_LEVEL_3: List[str] = OWASP_ASVS_40_LEVEL_2 + [
        "1.11.3", "2.2.4", "2.2.5", "2.2.6", "2.2.7", "2.8.7", "3.6.1", "3.6.2", "6.2.7", "6.2.8", "6.3.3", "8.1.5",
        "8.1.6", "9.2.5", "10.1.1", "10.2.3", "10.2.4", "10.2.5", "10.2.6", "14.1.5"
    ]
    
    OWASP_ASVS_40_REQUIREMENTS_BY_LEVEL: Dict[int, List[str]] = {
        1: OWASP_ASVS_40_LEVEL_1,
        2: OWASP_ASVS_40_LEVEL_2,
        3: OWASP_ASVS_40_LEVEL_3
    }
    
    # CWES by CASA category
    CWES_BY_CASA_CATEGORY: Dict[str, str] = {
        "1.1.4": "1059",
        "1.14.6": "477",
        "1.4.1": "602",
        "1.8.1": None,
        "1.8.2": None,
        "2.1.1": "521",
        "2.3.1": "330",
        "2.4.1": "916",
        "2.5.4": "16",
        "2.6.1": "308",
        "2.7.2": "287",
        "2.7.6": "310",
        "3.3.1": "613",
        "3.3.3": "613",
        "3.4.1": "614",
        "3.4.2": "1004",
        "3.4.3": "1275",
        "3.5.2": "798",
        "3.5.3": "345",
        "3.7.1": "306",
        "4.1.1": "602",
        "4.1.2": "639",
        "4.1.3": "285",
        "4.1.5": "285",
        "4.2.1": "639",
        "4.2.2": "352",
        "4.3.1": "419",
        "4.3.2": "548",
        "5.1.1": "235",
        "5.1.5": "601",
        "5.2.3": "147",
        "5.2.4": "95",
        "5.2.5": "94",
        "5.2.6": "918",
        "5.2.7": "159",
        "5.3.1": "116",
        "5.3.10": "643",
        "5.3.3": "79",
        "5.3.4": "89",
        "5.3.6": "830",
        "5.3.7": "90",
        "5.3.8": "78",
        "5.3.9": "829"
    }
    
    @classmethod
    def get_cwe_by_sq_category(cls, category: SQCategory) -> Set[str]:
        """Get CWE IDs for a SonarQube category"""
        return cls.CWES_BY_SQ_CATEGORY.get(category, set())
    
    @classmethod
    def get_sq_category_by_cwe(cls, cwe: str) -> Set[SQCategory]:
        """Get SonarQube categories for a CWE ID"""
        categories = set()
        for category, cwes in cls.CWES_BY_SQ_CATEGORY.items():
            if cwe in cwes:
                categories.add(category)
        return categories
    
    @classmethod
    def get_owasp_top_10_2017_by_cwe(cls, cwe: str) -> Set[str]:
        """Get OWASP Top 10 2017 categories for a CWE ID"""
        categories = set()
        for category, cwes in cls.OWASP_TOP_10_2017_MAPPINGS.items():
            if cwe in cwes:
                categories.add(category)
        return categories
    
    @classmethod
    def get_owasp_top_10_2021_by_cwe(cls, cwe: str) -> Set[str]:
        """Get OWASP Top 10 2021 categories for a CWE ID"""
        categories = set()
        for category, cwes in cls.OWASP_TOP_10_2021_MAPPINGS.items():
            if cwe in cwes:
                categories.add(category)
        return categories
    
    @classmethod
    def get_sans_top_25_by_cwe(cls, cwe: str) -> Set[str]:
        """Get SANS Top 25 categories for a CWE ID"""
        categories = set()
        for category, cwes in cls.CWES_BY_SANS_TOP_25.items():
            if cwe in cwes:
                categories.add(category)
        return categories
    
    @classmethod
    def is_security_hotspot(cls, rule_key: str) -> bool:
        """Check if a rule is a security hotspot"""
        # This would typically be determined by the rule configuration
        # For now, return False as most vulnerabilities are not hotspots
        return False
    
    @classmethod
    def get_vulnerability_probability(cls, sq_category: SQCategory) -> VulnerabilityProbability:
        """Get vulnerability probability for a SonarQube category"""
        high_risk_categories = {
            SQCategory.SQL_INJECTION,
            SQCategory.XSS,
            SQCategory.COMMAND_INJECTION,
            SQCategory.RCE,
            SQCategory.XXE
        }
        
        medium_risk_categories = {
            SQCategory.CSRF,
            SQCategory.OPEN_REDIRECT,
            SQCategory.LOG_INJECTION,
            SQCategory.LDAP_INJECTION,
            SQCategory.XPATH_INJECTION
        }
        
        if sq_category in high_risk_categories:
            return VulnerabilityProbability.HIGH
        elif sq_category in medium_risk_categories:
            return VulnerabilityProbability.MEDIUM
        else:
            return VulnerabilityProbability.LOW 