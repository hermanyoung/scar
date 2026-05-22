"""CWE-502: Insecure deserialization via pickle and yaml."""
import pickle
import yaml


def load_pickle_data(data: bytes) -> any:
    # CWE-502: pickle.loads on untrusted data
    return pickle.loads(data)


def load_yaml_unsafe(content: str) -> any:
    # CWE-502: yaml.load without SafeLoader
    return yaml.load(content, Loader=yaml.Loader)


def load_pickle_file(path: str) -> any:
    # CWE-502: pickle.load from file
    with open(path, "rb") as f:
        return pickle.load(f)
