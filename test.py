def chunks(l, n):
    """Yield n number of striped chunks from l."""
    for i in range(0, n):
        yield l[i::n]

test_list = list(zip(range(10), range(10)))
for chunk in chunks(test_list,3):
    print(chunk)