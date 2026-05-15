from __future__ import annotations


def unsupported_cloud_connector(name: str) -> None:
    raise RuntimeError(
        f"{name} folder scanning requires a customer-network agent with cloud SDK credentials. "
        "The source type is part of the contract; install the provider SDK and implement object listing/fetching here."
    )
