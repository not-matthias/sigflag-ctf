magic = [0x67, 0x45
, 0x8b 
, 0x6b 
, 0xc6 
, 0x23 
, 0x7b 
, 0x32 
, 0x69 
, 0x98 
, 0x3c 
, 0x64 
, 0x73 
, 0x48 
, 0x33 
, 0x66 ]

magic2 = [
0x34,  
0x0c,  
0xcc,  
0x10,  
0xf7,  
0x10,  
0x48,  
0x05,  
0x36,  
0xf0,  
0x08,  
0x1c,  
0x0b,  
0x78,  
0x41,  
0x1b,  
]

print(len(magic))

for i in range(0, len(magic)):
    print(chr(magic[i] ^ magic2[i]), end="")