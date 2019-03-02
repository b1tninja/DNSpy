aiodns / dnspy
=====

asyncio dns library

DnsServer code suitable for sniffing dns traffic or responding to clients. See the example usage in __main__ that
acts as a recursive resolver. (Recursion desired = 0)

DnsResolver is a beast and is in desperate need of cleanup... but it is a semi functional recursive resolver.

DomainName parsing should be pretty solid... except I don't currently support any of the ACE Prefixes / IDN /
 punycode or anything of the sort (ie: xn--). 
 
In process of porting code to Python 3, and restructuring as a module.
 
Master branch is WIP, not stable at this point. As it matures, I'll switch to another banch for dev...
  
