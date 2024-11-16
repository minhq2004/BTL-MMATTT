from EllipticCurve import *
import random
import re

p = 29
A, B = random.randint(0, p), random.randint(0,p)


E = EllipticCurve(p, A, B)
order = E.sea()
n = int(re.search(r'\d+', order).group())

print(n)
print("128-bit example with SEA: ", order)

#Example Output (will be random):
#SEA:  #E(F_p) = 201
#Schoof:  #E(F_p) = 201
#Baby-step giant-step:  #E(F_p) = 201
#128-bit example with SEA:  #E(F_p) = 340282366920938463470648655491441425069 (Compute time ~5 seconds)
