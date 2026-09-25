"""Secrets: Windows Credential Manager (via keyring) first, environment variable as fallback.

Store a secret once, as the account that runs the pipeline:
    python -c "import keyring; keyring.set_password('stenwatch', 'NVD_API_KEY', input('key: '))"
"""
import os

SERVICE = "stenwatch"


def secret(name):
    try:
        import keyring
        value = keyring.get_password(SERVICE, name)
        if value:
            return value
    except Exception:  # keyring missing or no backend: fall back to the environment
        pass
    return os.environ.get(name)
