from __future__ import annotations

from dataclasses import dataclass, field

from phi_guard_scanner.classifiers.patterns import normalized_name, text_pattern_labels, value_pattern_labels
from phi_guard_scanner.models import Classification, ClassificationLabel


DIRECT_IDENTIFIER_NAMES = {
    "name",
    "full_name",
    "first_name",
    "last_name",
    "email",
    "email_address",
    "phone",
    "phone_number",
    "mobile_phone",
    "ssn",
    "social_security_number",
    "mrn",
    "medical_record_number",
    "member_number",
    "account_number",
    "subscriber_id",
}

QUASI_IDENTIFIER_NAMES = {
    "dob",
    "date_of_birth",
    "birth_date",
    "zip",
    "zipcode",
    "postal_code",
    "address",
    "street_address",
    "city",
    "state",
    "gender",
    "age",
    "service_date",
    "encounter_date",
    "appointment_date",
    "created_at",
}

HEALTH_CONTEXT_HINTS = {
    "diagnosis",
    "diagnosis_code",
    "condition",
    "condition_code",
    "medication",
    "medication_name",
    "lab",
    "lab_result",
    "result_value",
    "encounter",
    "procedure",
    "procedure_code",
    "allergy",
    "immunization",
    "clinical",
    "notes",
}

PAYMENT_CONTEXT_HINTS = {
    "claim",
    "claim_id",
    "claim_amount",
    "payer",
    "insurer",
    "billing",
    "payment",
    "balance",
    "copay",
    "account_balance",
    "invoice",
}

FREE_TEXT_HINTS = {
    "note",
    "notes",
    "comment",
    "comments",
    "description",
    "message",
    "body",
    "raw_text",
    "prompt",
    "log",
    "ticket",
}

LINKABLE_KEYS = {
    "patient_id",
    "member_id",
    "person_id",
    "encounter_id",
    "claim_id",
    "account_id",
    "appointment_id",
}

AI_TOKEN_HINTS = {"ai", "prompt", "embedding", "vector", "model", "llm"}
AI_SUBSTRING_HINTS = {"prompt", "embedding", "vector", "model", "llm"}


@dataclass(frozen=True)
class ColumnProfile:
    table_name: str
    column_name: str
    data_type: str
    sample_shapes: list[str] = field(default_factory=list)


def classify_column(profile: ColumnProfile) -> list[Classification]:
    name = normalized_name(profile.column_name)
    table = normalized_name(profile.table_name)
    data_type = normalized_name(profile.data_type)
    name_tokens = set(name.split("_"))
    table_tokens = set(table.split("_"))
    tokens = name_tokens | table_tokens
    value_labels = value_pattern_labels(profile.sample_shapes)
    text_labels = text_pattern_labels(profile.sample_shapes)
    classifications: list[Classification] = []

    def add(label: ClassificationLabel, confidence: float, source: str, **details: object) -> None:
        existing = [item for item in classifications if item.label == label]
        if existing and existing[0].confidence >= confidence:
            return
        classifications[:] = [item for item in classifications if item.label != label]
        classifications.append(Classification(label=label, confidence=confidence, source=source, details=details))

    direct_pattern_labels = value_labels & {"email", "phone", "ssn"} | text_labels & {"email", "phone", "ssn", "mrn", "name"}
    if name in DIRECT_IDENTIFIER_NAMES or direct_pattern_labels:
        add(
            ClassificationLabel.DIRECT_IDENTIFIER,
            0.95 if value_labels & {"email", "phone", "ssn"} else 0.9 if direct_pattern_labels else 0.88,
            "value_pattern" if direct_pattern_labels and name not in DIRECT_IDENTIFIER_NAMES else "column_name+pattern" if direct_pattern_labels else "column_name",
            matched_name=name,
            value_patterns=sorted(value_labels | text_labels),
        )

    if "mrn" in name or "medical_record" in name:
        add(ClassificationLabel.DIRECT_IDENTIFIER, 0.94, "column_name", matched_name=name)

    contextual_zip = "zip" in value_labels and (name in {"zip", "zipcode", "postal_code"} or tokens & {"zip", "zipcode", "postal", "address"})
    contextual_date = "date" in value_labels and (
        "date" in name or name in {"dob", "date_of_birth", "birth_date"} or any(kind in data_type for kind in ["date", "time"])
    )
    contextual_ip = "ip" in value_labels and (name in {"ip", "ip_address"} or "inet" in data_type)
    text_quasi = text_labels & {"dob", "date", "address_term", "street_address", "geography", "zip"}
    if name in QUASI_IDENTIFIER_NAMES or contextual_zip or contextual_date or contextual_ip or text_quasi:
        add(
            ClassificationLabel.QUASI_IDENTIFIER,
            0.9 if contextual_zip or contextual_date or contextual_ip or text_quasi else 0.82,
            "value_pattern" if (contextual_zip or contextual_date or contextual_ip or text_quasi) and name not in QUASI_IDENTIFIER_NAMES else "column_name",
            matched_name=name,
            value_patterns=sorted(value_labels | text_labels),
        )

    health_pattern_match = (
        "icd10" in value_labels
        or "icd10" in text_labels
        or "health_term" in text_labels
        or "mental_health_term" in text_labels
        or ("cpt" in value_labels and ("procedure" in name or "cpt" in name))
        or ("npi" in value_labels and ("provider" in name or "npi" in name))
    )
    if name in HEALTH_CONTEXT_HINTS or tokens & HEALTH_CONTEXT_HINTS or health_pattern_match:
        add(
            ClassificationLabel.HEALTH_CONTEXT,
            0.88 if value_labels else 0.78,
            "column_name+pattern" if value_labels else "column_name",
            matched_name=name,
            value_patterns=sorted(value_labels | text_labels),
        )

    if name in PAYMENT_CONTEXT_HINTS or tokens & PAYMENT_CONTEXT_HINTS:
        add(ClassificationLabel.PAYMENT_CONTEXT, 0.82, "column_name", matched_name=name)

    if name in LINKABLE_KEYS or name.endswith("_id") and ("uuid" in data_type or "int" in data_type):
        add(ClassificationLabel.LINKABLE_KEY, 0.86, "column_name", matched_name=name)

    if (
        name in FREE_TEXT_HINTS
        or name_tokens & FREE_TEXT_HINTS
        or any(hint in name for hint in FREE_TEXT_HINTS)
    ) and any(kind in data_type for kind in ["text", "json", "varchar", "char"]):
        add(
            ClassificationLabel.FREE_TEXT_PHI_RISK,
            0.84,
            "column_name+type",
            matched_name=name,
            data_type=profile.data_type,
        )

    if tokens & AI_TOKEN_HINTS or any(hint in name for hint in AI_SUBSTRING_HINTS) or "ai_term" in text_labels:
        add(ClassificationLabel.AI_EXPOSURE_RISK, 0.86, "column_name", matched_name=name)

    if any(
        item.label
        in {
            ClassificationLabel.DIRECT_IDENTIFIER,
            ClassificationLabel.QUASI_IDENTIFIER,
            ClassificationLabel.FREE_TEXT_PHI_RISK,
        }
        for item in classifications
    ):
        add(ClassificationLabel.DEIDENTIFICATION_BLOCKER, 0.8, "classification_rollup", matched_name=name)

    return sorted(classifications, key=lambda item: item.label.value)


def has_label(classifications: list[Classification], label: ClassificationLabel) -> bool:
    return any(item.label == label for item in classifications)
