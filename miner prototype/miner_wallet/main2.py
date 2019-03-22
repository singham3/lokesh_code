# main.py
class A:
    def __init__(self):
        self.sd = "None"

def D():
    A()


def G():

    print(A.sd)

if __name__ == "__main__":
    D()
    A.sd = "hello world"






