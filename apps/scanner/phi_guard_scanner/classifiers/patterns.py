from __future__ import annotations

import re


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}$")
SSN_RE = re.compile(r"^\d{3}-?\d{2}-?\d{4}$")
ICD10_RE = re.compile(r"^[A-TV-Z][0-9][0-9A-Z](?:\.[0-9A-Z]{1,4})?$", re.IGNORECASE)
CPT_RE = re.compile(r"^\d{5}$")
NPI_RE = re.compile(r"^\d{10}$")
IP_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IP_RE = re.compile(rf"^{IP_OCTET}(?:\.{IP_OCTET}){{3}}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$|^\d{1,2}/\d{1,2}/\d{2,4}$")
ZIP_RE = re.compile(r"^\d{5}(?:-\d{4})?$")
EMBEDDED_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
EMBEDDED_PHONE_RE = re.compile(r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")
EMBEDDED_SSN_RE = re.compile(r"\b\d{3}-?\d{2}-?\d{4}\b")
EMBEDDED_MRN_RE = re.compile(r"\b(?:MRN|medical record)[:#\s-]*[A-Za-z0-9-]{4,}\b", re.IGNORECASE)
EMBEDDED_NAME_RE = re.compile(
    r"\b(?:patient|member|subscriber|name)[:#\s-]*(?:[A-Z][a-z]+)(?:\s+[A-Z]\.)?\s+[A-Z][a-z]+\b"
    r"|\b[A-Z][a-z]+(?:\s+[A-Z]\.)?\s+[A-Z][a-z]+,\s+(?:admitted|diagnosed|treated|seen)\b",
    re.IGNORECASE,
)
EMBEDDED_DOB_RE = re.compile(
    r"\b(?:DOB|date of birth)[:#\s-]*(?:\d{1,2}/\d{1,2}/\d{2,4}|\d{4}-\d{2}-\d{2})\b",
    re.IGNORECASE,
)
EMBEDDED_ICD10_RE = re.compile(r"\b[A-TV-Z][0-9][0-9A-Z](?:\.[0-9A-Z]{1,4})?\b", re.IGNORECASE)
STREET_ADDRESS_RE = re.compile(
    r"\b\d{1,6}\s+[A-Za-z0-9.'-]+(?:\s+[A-Za-z0-9.'-]+){0,4}\s+"
    r"(?:st|street|ave|avenue|rd|road|dr|drive|blvd|boulevard|ln|lane|ct|court|way|pkwy|parkway)\b",
    re.IGNORECASE,
)
CITY_STATE_RE = re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?,\s+[A-Z]{2}\b")
EMBEDDED_ZIP_RE = re.compile(r"\b\d{5}(?:-\d{4})?\b")
HEALTH_TERM_RE = re.compile(
    r"\b(?:diagnosis|diagnosed|admitted|patient|prescription|medication|lab|claim|encounter|condition|allergy|treatment|provider|mrn|medical record|dob|acute myocardial infarction|myocardial infarction)\b",
    re.IGNORECASE,
)
ADDRESS_TERM_RE = re.compile(r"\b(?:street|avenue|road|drive|blvd|apt|suite|address)\b", re.IGNORECASE)
MENTAL_HEALTH_TERM_RE = re.compile(
    r"\b(?:schizophrenia|bipolar|psychosis|ptsd|post-traumatic stress|major depressive|depression|psychiatric|mental health|substance use|suicidal ideation)\b",
    re.IGNORECASE,
)
AI_TERM_RE = re.compile(r"\b(?:prompt|embedding|vector|llm|model)\b", re.IGNORECASE)


def normalized_name(value: str) -> str:
    return value.lower().replace("-", "_").replace(" ", "_")


def value_pattern_labels(sample_shapes: list[str]) -> set[str]:
    labels: set[str] = set()
    for sample in sample_shapes:
        value = sample.strip()
        if EMAIL_RE.match(value):
            labels.add("email")
        if PHONE_RE.match(value):
            labels.add("phone")
        if SSN_RE.match(value):
            labels.add("ssn")
        if ICD10_RE.match(value):
            labels.add("icd10")
        if CPT_RE.match(value):
            labels.add("cpt")
        if NPI_RE.match(value):
            labels.add("npi")
        if IP_RE.match(value):
            labels.add("ip")
        if DATE_RE.match(value):
            labels.add("date")
        if ZIP_RE.match(value):
            labels.add("zip")
    return labels


def text_pattern_labels(sample_shapes: list[str]) -> set[str]:
    labels: set[str] = set()
    for sample in sample_shapes:
        value = sample.strip()
        if not value:
            continue
        if EMBEDDED_EMAIL_RE.search(value):
            labels.add("email")
        if EMBEDDED_PHONE_RE.search(value):
            labels.add("phone")
        if EMBEDDED_SSN_RE.search(value):
            labels.add("ssn")
        if EMBEDDED_MRN_RE.search(value):
            labels.add("mrn")
        if EMBEDDED_NAME_RE.search(value):
            labels.add("name")
        if EMBEDDED_DOB_RE.search(value):
            labels.add("dob")
            labels.add("date")
        if EMBEDDED_ICD10_RE.search(value) and HEALTH_TERM_RE.search(value):
            labels.add("icd10")
        if HEALTH_TERM_RE.search(value):
            labels.add("health_term")
        if MENTAL_HEALTH_TERM_RE.search(value):
            labels.add("mental_health_term")
            labels.add("health_term")
        if STREET_ADDRESS_RE.search(value):
            labels.add("street_address")
            labels.add("address_term")
            labels.add("geography")
        if CITY_STATE_RE.search(value):
            labels.add("geography")
        if EMBEDDED_ZIP_RE.search(value) and (STREET_ADDRESS_RE.search(value) or ADDRESS_TERM_RE.search(value)):
            labels.add("zip")
            labels.add("geography")
        if ADDRESS_TERM_RE.search(value):
            labels.add("address_term")
        if AI_TERM_RE.search(value):
            labels.add("ai_term")
    return labels


def masked_shape(kind: str) -> str:
    examples = {
        "email": "j***@example.test",
        "name": "J*** P*****",
        "phone": "***-***-0142",
        "ssn": "***-**-6789",
        "mrn": "MRN-****2048",
        "date": "yyyy-mm-dd",
        "zip": "021**",
        "ip": "10.***.***.42",
        "street_address": "123 *** St",
        "geography": "city/state-level location detected",
        "notes": "contains phone-like/date-like/address-like tokens",
        "diagnosis": "ICD10-like code",
        "account": "acct_****9120",
    }
    return examples.get(kind, "masked pattern detected")
