
import random
import uuid
from base64 import b64encode
from secrets import token_bytes


import ruamel.yaml
yaml = ruamel.yaml.YAML()

s_num = 1010
user_num = 40

users = []

for n in range(s_num, s_num+user_num):
  _u = {
    "name": f"user{n}",
    "nickname": f"user{n}",
    "password": b64encode(token_bytes(16)).decode(),
    "uuid_str":str(uuid.uuid4()),
    "auth": str(random.random())[-6:]
  }
  users.append(_u)

res={"users":users}


yaml.dump(res, open('runtime/users.yaml', 'w+'))


