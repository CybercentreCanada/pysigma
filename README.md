# Sigma Signature Library
The Sigma Signature Library works by parsing Sigma rules in a Python environment in order to evaluate Sysmon event logs and report any matches (or hits) for the logs. 

For more info on Sigma visit https://github.com/Neo23x0/sigma.

# How does it work?
The library handles the signature syntax of Sigma using Lark, which is a modern parsing library for Python. Lark is able to parse any context-free grammar and returns an output using automatic tree construction. In the context of the library, Lark is used to evaluate the condition strings within the Sigma rules and return true or false for the given Sysmon event log. 

For more info on Lark, visit https://lark-parser.readthedocs.io/en/latest/.

# Example

# How do I run it?

# Work in Progress
 
# Credits
