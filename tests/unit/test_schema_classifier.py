from phi_guard_scanner.classifiers.schema_classifier import ColumnProfile, classify_column


def labels_for(profile: ColumnProfile) -> set[str]:
    return {classification.label.value for classification in classify_column(profile)}


def test_email_is_direct_identifier_not_ai_exposure() -> None:
    labels = labels_for(
        ColumnProfile(
            table_name="patients",
            column_name="email",
            data_type="text",
            sample_shapes=["alex.rivera@example.test"],
        )
    )

    assert "DIRECT_IDENTIFIER" in labels
    assert "DEIDENTIFICATION_BLOCKER" in labels
    assert "AI_EXPOSURE_RISK" not in labels


def test_prompt_text_is_free_text_and_ai_exposure() -> None:
    labels = labels_for(
        ColumnProfile(
            table_name="ai_prompt_logs",
            column_name="prompt_text",
            data_type="text",
            sample_shapes=["contains patient detail pattern"],
        )
    )

    assert "FREE_TEXT_PHI_RISK" in labels
    assert "AI_EXPOSURE_RISK" in labels


def test_zip_sample_is_quasi_identifier_not_health_context() -> None:
    labels = labels_for(
        ColumnProfile(
            table_name="patients",
            column_name="zip",
            data_type="text",
            sample_shapes=["02139"],
        )
    )

    assert "QUASI_IDENTIFIER" in labels
    assert "HEALTH_CONTEXT" not in labels


def test_invalid_ip_like_value_is_not_a_quasi_identifier() -> None:
    labels = labels_for(
        ColumnProfile(
            table_name="system_events",
            column_name="ip_address",
            data_type="text",
            sample_shapes=["999.999.999.999"],
        )
    )

    assert "QUASI_IDENTIFIER" not in labels


def test_operational_metric_is_not_misread_as_zip_or_cpt() -> None:
    labels = labels_for(
        ColumnProfile(
            table_name="hipaa_stress_test_data",
            column_name="memory_usage_mb",
            data_type="integer",
            sample_shapes=["02139", "14200", "48125"],
        )
    )

    assert "QUASI_IDENTIFIER" not in labels
    assert "HEALTH_CONTEXT" not in labels


def test_embedded_phi_in_log_text_is_classified() -> None:
    labels = labels_for(
        ColumnProfile(
            table_name="system_logs",
            column_name="log_message",
            data_type="text",
            sample_shapes=[
                "Failed export for patient DOB: 01/02/1980 MRN: A12345 SSN 123-45-6789 diagnosis E11.9 email alex@example.test"
            ],
        )
    )

    assert "DIRECT_IDENTIFIER" in labels
    assert "HEALTH_CONTEXT" in labels
    assert "FREE_TEXT_PHI_RISK" in labels
    assert "DEIDENTIFICATION_BLOCKER" in labels


def test_full_name_address_and_mental_health_context_in_log_text_are_classified() -> None:
    classifications = classify_column(
        ColumnProfile(
            table_name="system_logs",
            column_name="log_message",
            data_type="text",
            sample_shapes=[
                "Patient John Q. Public, admitted for Acute Myocardial Infarction at 123 Maple St, Appleton, WI. Diagnosis: Schizophrenia."
            ],
        )
    )
    labels = {classification.label.value for classification in classifications}
    patterns = {
        pattern
        for classification in classifications
        for pattern in classification.details.get("value_patterns", [])
    }

    assert "DIRECT_IDENTIFIER" in labels
    assert "HEALTH_CONTEXT" in labels
    assert "QUASI_IDENTIFIER" in labels
    assert "FREE_TEXT_PHI_RISK" in labels
    assert {"name", "street_address", "geography", "mental_health_term"}.issubset(patterns)
