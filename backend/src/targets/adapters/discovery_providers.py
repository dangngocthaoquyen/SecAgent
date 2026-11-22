"""Replaceable target adapter discovery registry."""

from targets.adapters.dvaa_discovery import DvaaEvidenceDiscoveryProvider


def evidence_discovery_providers():
    return (DvaaEvidenceDiscoveryProvider(),)
