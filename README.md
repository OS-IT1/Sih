---
title: "Smooth Criminal"
date: 2026-03-15T22:58:02+05:30
tags: ['beginner']
categories: ['crypto'] # for | crypto | osint | rev | pwn 
authors: ['pastimeplays']
description: "I like the theory behind this one"
---

# Smooth Criminal

<!-- DESCRIPTION -->
> Our cryptographer assured us that a 649-bit prime makes this completely unbreakable. He also said the order of the group "doesn't really matter that much." He no longer works here.

points: `100`

solves: `496`

handouts: [`dlp.txt`]

author: `@GarvK07`

---

## Challenge Description
This challenge is built upon the Discrete Logarithm Problem (DLP). For those of you new to it, it is the problem of finding an $a$ given $g,h,p$ where 
$$g^a \equiv h\ (mod\ p)$$
(there's more to it, but that's the basic idea)

```
The flag has been encoded as a secret exponent x, where:

  h = g^x mod p

Your job: find x. Convert it from integer to bytes to get the flag.

p = 1363402168895933073124331075716158793413739602475544713040662303260999503992311247861095036060712607168809958344896622485452229880797791800555191761456659256252204001928525518751268009081850267001
g = 223
h = 1009660566883490917987475170194560289062628664411983200474597006489640893063715494610197294704009188265361176318190659133132869144519884282668828418392494875096149757008157476595873791868761173517
```

There are many algorithms that make the recovery of discrete logs faster, but under ideal conditions, for numbers as big as the one used, it is still computationally very very expensive to calculate the discrete log $a$. \
Luckily, this isn't one of them.

--- 

## Solution
You can use many tools to directly solve this for you, for example, you can use sage as follows - 
```sage
p = 1363402168895933073124331075716158793413739602475544713040662303260999503992311247861095036060712607168809958344896622485452229880797791800555191761456659256252204001928525518751268009081850267001
F = Zmod(p)             # Zmod creates an Integer field mod the number inside
g = F(223)
h = F(1009660566883490917987475170194560289062628664411983200474597006489640893063715494610197294704009188265361176318190659133132869144519884282668828418392494875096149757008157476595873791868761173517)

print(discrete_log(h,g))

# 810642462826781236630409314742801724164468986543937060322593530182136957 
# Converting this to bytes will give you the flag
``` 
So if you wanted a direct solution, this is it.

### Pohlig Hellman attack

Now I'm gonna talk about the actual attack behind this given value for those of you interested in the math.
I will be assuming familiarity with some basic group theory in the following explanation.

Starting off, we know that $p$ is prime, so the order of its modular ring (and all its generators) will be $p-1$, and the fact that any element of the group, when raised to the order, will be $1\ (mod\ p)$ 

What makes finding $a$ difficult is the fact that in large groups, simply going through all powers is not practical, considering how large the order is. However this is something that is very feasible for lower orders.\
So is it possible to convert the problem of finding a larger discrete log to a few smaller discrete logs?\
When the order is smooth (has small factors), YES.

This is exactly the case with our current challenge. Checking for its factors online ([factordb.com](https://factordb.com/index.php?query=1363402168895933073124331075716158793413739602475544713040662303260999503992311247861095036060712607168809958344896622485452229880797791800555191761456659256252204001928525518751268009081850267000)) shows us that its factors are all well under 200. So how do we break this into smaller problems?

Let $x = x_0\cdot x_1 \dots x_n$.\
Now if the order of a generator $g$ is $x$, it means that in its corresponding group, $g^x = 1$. \
Let's define &nbsp; $X_0$ as $\frac{x}{x_0}$ &nbsp; and &nbsp; $g_0$ as $g^{X_0}$ &nbsp; (still in the corresponding mod group).\
This directly implies that the order of $g_0$ is $x_0$, since $$g_0^{x_0} = g^{X_0 \cdot x_0} = g ^ {x} = 1$$
If I want to find a discrete log with the $g_0$ as the base, now I only need to deal with an order of $x_0$ instead of the entire $x$. 

So how do we apply this to our situation?\
We can factorise the order of the group we have into much smaller factors, each translating to a smaller problem, that gives us some information about the hidden exponent. \
Let $p = p_0^{e_0}\cdot p_1^{e_1} \dots p_n^{e_n}$, $P_i = \frac{p}{p_i^{e_i}}$, and $g_i, h_i = g^{P_i}, h^{P_i}$ according to the above convention. If we create smaller problems with respect to each of the prime factors $p_i$ (using $p_i^{e_i}$) as follows - 
$$
\begin{gather*}
g^{a}\equiv h\ (mod\ p) \\
(g^{a})^{P_i}\equiv h^{P_i}\ (mod\ p) \\
(g^{P_i})^{a}\equiv h^{P_i}\ (mod\ p) \\
g_i^{a} \equiv h_i\ (mod\ p) \\
\end{gather*}
$$

We know that each $g_i$ will have a much smaller order, so it will be easy to solve this discrete log problem with the new base. But as you can probably see, the answer is not going to match but that's to be expected, since we end up with a value lesser that $p_i^{e_i}$, which will obviously be much smaller than the actual answer, considering how large $p$ is.\
Although it doesn't give us the actual value of $a$, we recover the value of $a\ (mod\ p_i^{e_i})$ (Why? Think!)

Once we recover the values of $a$ modulo every prime factor of $p$, we can simply use the Chinese Remainder Theorem to combine them and recover the value of the actual $a$.

---

## Code

```python
from Crypto.Util.number import *

def crt(remainders : list, modulos : list) -> int:
    N = 1
    
    # This is the classic method of recovering a modulo p,  given a modulo p1, p2, p3, ... where all factors are pairwise cop
    for factor in modulos:
        N *= factor
    Nis = []
    for factor in modulos:
        Nis.append(N//factor)
        
    ans = 0
    
    for i in range(len(remainders)):
        ans += remainders[i] * Nis[i] * pow(Nis[i],-1,modulos[i])
        ans %= N
    
    return ans


def pohlig_hellman(p : int, h : int, g : int) -> int:
    # Order of group
    phi = p-1
    # Factorise
    factors = []
    i = 2
    while phi>1:
        pr = i
        exp = 0
        while phi%pr == 0:
            phi //= pr
            exp +=1
        if exp>0:
            factors.append((pr, exp))
        i += 1
    
    phi = p-1
    factors = factors
    print("Factors of the order - ")
    print(factors)
    
    modulos, remainders = [], []
    
    # Solve for each new sub problem by bruteforcing
    for prime, power in factors:
        factor = 1
        
        # This is a limit imposed by me since we are running python. It might lead to missing the answer in sometimes, but it's enough for this problem
        while(factor*prime<10**6 and power>0):
            factor = factor*prime
            power -= 1
        exp = phi//factor
        
        # Create new g_i and h_i
        g_i = pow(g,exp,p)
        h_i = pow(h,exp,p)
        
        # Bruteforce for the correct exponent (this might take a while if the factor is large)
        val = 0
        while(pow(g_i,val,p)!=h_i):
            val += 1
            if val==factor:
                exit()          # This means something went wrong
        
        # Recover information about a
        print(f'a = {val} (mod {factor})')
        modulos.append(factor)
        remainders.append(val)
        
    # Perform CRT to get answer
    return crt(remainders, modulos)

h = 1009660566883490917987475170194560289062628664411983200474597006489640893063715494610197294704009188265361176318190659133132869144519884282668828418392494875096149757008157476595873791868761173517
p = 1363402168895933073124331075716158793413739602475544713040662303260999503992311247861095036060712607168809958344896622485452229880797791800555191761456659256252204001928525518751268009081850267001
g = 223

print(long_to_bytes(pohlig_hellman(p=p,h=h,g=g)))
```
### Output
```
Factors of the order - 
[(2, 3), (3, 3), (5, 3), (7, 2), (11, 3), (13, 3), (17, 3), (19, 1), (23, 2), (29, 2), (31, 3), (37, 2), (41, 2), (43, 2), (47, 3), (53, 3), (59, 3), (61, 1), (67, 3), (71, 2), (73, 1), (79, 3), (83, 2), (89, 3), (97, 4), (101, 2), (103, 1), (107, 2), (109, 1), (113, 2), (127, 7), (131, 2), (137, 3), (139, 1), (149, 5), (151, 1), (157, 3), (163, 3), (167, 2), (173, 3), (179, 3), (181, 1), (191, 5), (193, 1), (197, 1)]
a = 5 (mod 8)
a = 25 (mod 27)
a = 82 (mod 125)
a = 6 (mod 49)
a = 884 (mod 1331)
a = 1290 (mod 2197)
a = 1717 (mod 4913)
a = 16 (mod 19)
a = 40 (mod 529)
a = 443 (mod 841)
a = 20619 (mod 29791)
a = 564 (mod 1369)
a = 842 (mod 1681)
a = 653 (mod 1849)
a = 60937 (mod 103823)
a = 145241 (mod 148877)
a = 21485 (mod 205379)
a = 7 (mod 61)
a = 51855 (mod 300763)
a = 3046 (mod 5041)
a = 42 (mod 73)
a = 267940 (mod 493039)
a = 666 (mod 6889)
a = 697418 (mod 704969)
a = 726026 (mod 912673)
a = 1793 (mod 10201)
a = 85 (mod 103)
a = 11291 (mod 11449)
a = 95 (mod 109)
a = 6218 (mod 12769)
a = 11929 (mod 16129)
a = 9717 (mod 17161)
a = 7370 (mod 18769)
a = 24 (mod 139)
a = 3072 (mod 22201)
a = 114 (mod 151)
a = 16341 (mod 24649)
a = 13214 (mod 26569)
a = 8527 (mod 27889)
a = 22414 (mod 29929)
a = 9529 (mod 32041)
a = 68 (mod 181)
a = 3902 (mod 36481)
a = 12 (mod 193)
a = 103 (mod 197)
b'utflag{sm00th_cr1m1nal_caught}'
```
---

```
utflag{sm00th_cr1m1nal_caught}
```
