"""Discrete empirical entropy estimators. No claims of causal information or compression lower bound for individual strings."""
import math
from collections import Counter

def entropy(values):
    vals=list(values)
    if not vals: return 0.0
    counts=Counter(vals)
    n=len(vals)
    return -sum((v/n)*math.log2(v/n) for v in counts.values())

def conditional_entropy(values):
    """Empirical H(X_i | X_{i-1}), one-step Markov approximation, bits/symbol."""
    vals=list(values)
    if len(vals)<2: return 0.0
    pairs=Counter(zip(vals[:-1],vals[1:]))
    prev=Counter(vals[:-1])
    n=len(vals)-1
    return sum((count/n)*(-math.log2(count/prev[a])) for (a,b),count in pairs.items())

def binary_entropy(p):
    if not 0<=p<=1: raise ValueError('probability outside 0..1')
    return sum(-q*math.log2(q) for q in (p,1-p) if q)

def demo():
    rgb=[64,128,192]*1000
    return {'rgb_symbol_entropy':entropy(rgb),
            'rgb_one_step_conditional_entropy':conditional_entropy(rgb),
            'fair_binary_entropy':binary_entropy(0.5),
            'ten_percent_binary_entropy':binary_entropy(0.1)}
