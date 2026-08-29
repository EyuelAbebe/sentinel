"""Offline classification service — maps hostnames/IPs to org + privacy category."""

from __future__ import annotations

from datetime import UTC, datetime

from sentinel.adapters.tracker_lists import DATASET_VERSION, DOMAIN_DB
from sentinel.domain.classifications import ClassificationEvidence
from sentinel.domain.enums import IdentityStatus, PrivacyCategory


class ClassificationService:
    """Classifies domain names using the offline tracker database.

    Subdomain matching walks up the label hierarchy:
      analytics.example.com → example.com → not found → UNKNOWN
    """

    def classify(self, subject: str) -> ClassificationEvidence:
        """Return classification evidence for a hostname or IP address."""
        hostname = subject.lower().strip()

        entry = self._lookup(hostname)
        if entry is not None:
            org, category = entry
            return ClassificationEvidence(
                subject_type="domain",
                subject=subject,
                identity_status=IdentityStatus.KNOWN,
                organization=org,
                category=category,
                source="local",
                source_version=DATASET_VERSION,
                confidence=1.0,
                observed_at=datetime.now(UTC),
            )

        return ClassificationEvidence(
            subject_type="domain",
            subject=subject,
            identity_status=IdentityStatus.UNKNOWN,
            category=PrivacyCategory.UNKNOWN,
            source="local",
            source_version=DATASET_VERSION,
            confidence=0.0,
            observed_at=datetime.now(UTC),
        )

    def _lookup(self, hostname: str) -> tuple[str, PrivacyCategory] | None:
        """Walk subdomain hierarchy until a match is found."""
        labels = hostname.split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate in DOMAIN_DB:
                return DOMAIN_DB[candidate]
        return None

    def is_privacy_risk(self, evidence: ClassificationEvidence) -> bool:
        """Return True if the evidence category warrants a finding."""
        return evidence.category in (
            PrivacyCategory.TRACKING,
            PrivacyCategory.ADVERTISING,
        )
