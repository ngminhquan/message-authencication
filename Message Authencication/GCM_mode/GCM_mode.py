s = frozenset([1, 2, 3])
print(s)  # prints "frozenset({1, 2, 3})"

# Try to modify the frozenset
try:
    s.add(4)
except AttributeError as e:
    print(e)