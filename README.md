# Giant-Cipher-Solver
A Node.js CLI that helps crack / analyze the map’s ciphertext: it takes a Base64 string from cipherbase.json, decodes it, then runs heuristics (lore-style keys, XOR, Base64 alphabet tricks, Vigenère/Beaufort, nested Base64, zlib, RC4, layered transforms) and optional brute force with English scoring + a strict readability gate.
