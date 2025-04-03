# api_misuse
Python tool to analyze cryptographic API misuse in open source projects

## Problem Statement

The first rule of cryptography is, "Don't roll your own!" This means that programmers looking to add "security" to their application are going to leverage an existing cryptographic library (e.g., OpenSSL). Unfortunately, the most common cryptographic libraries are similar in complexity as rolling your own. Thus, a growing body of research seeks to identify misuses such cryptographic library's Application Programmer Interface (API). Note that a library's API is the set of ways that your software can interact with the library; there are secure and insecure ways to interact with a library. For this project, you will examine how a set of programs uses a cryptographic library's API. Conventionally, this analysis is intraprocedural, but your analysis will look at the opportunity and challenges of interprocedural API usage analysis. Your end goal is to identify API misuses.
