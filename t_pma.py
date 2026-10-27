import pma_spray as s

for u, p in (("root", "definitelywrongpass"), ("root", ""), ("admin", "zzz")):
    st, login = s.attempt(u, p)
    print(f"{u}:{p or '<empty>'} -> {st} login_form={login}")
