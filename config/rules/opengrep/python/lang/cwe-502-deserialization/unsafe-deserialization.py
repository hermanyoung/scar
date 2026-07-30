import pickle
import marshal
import shelve
import yaml
import jsonpickle

# ruleid: python.lang.security.cwe-502.unsafe-deserialization
obj = pickle.loads(data)

# ruleid: python.lang.security.cwe-502.unsafe-deserialization
obj = pickle.load(file_handle)

# ruleid: python.lang.security.cwe-502.unsafe-deserialization
db = shelve.open("data.db")

# ruleid: python.lang.security.cwe-502.unsafe-deserialization
obj = marshal.loads(data)

# ruleid: python.lang.security.cwe-502.unsafe-deserialization
obj = jsonpickle.decode(json_string)

# An explicit unsafe Loader trips both rules: the deserialization rule matches
# the Loader argument, the yaml rule matches the bare yaml.load call.
# ruleid: python.lang.security.cwe-502.unsafe-deserialization,python.lang.security.cwe-502.yaml-unsafe-load
obj = yaml.load(data, Loader=yaml.Loader)

# ruleid: python.lang.security.cwe-502.unsafe-deserialization
obj = yaml.unsafe_load(data)

# ok: python.lang.security.cwe-502.unsafe-deserialization
import json
obj = json.loads(data)

# ok: python.lang.security.cwe-502.unsafe-deserialization,python.lang.security.cwe-502.yaml-unsafe-load
obj = yaml.safe_load(data)

# ok: python.lang.security.cwe-502.unsafe-deserialization,python.lang.security.cwe-502.yaml-unsafe-load
obj = yaml.load(data, Loader=yaml.SafeLoader)
