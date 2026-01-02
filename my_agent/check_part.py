
from google.genai import types

p1 = types.Part(text="hello")
print(p1)
try:
    p2 = types.Part(function_call=types.FunctionCall(name="foo", args={"a": 1}))
    print(p2)
except Exception as e:
    print(e)
