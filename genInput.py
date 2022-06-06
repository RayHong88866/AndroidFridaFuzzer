from numpy import byte



out = ''
#for b in range(0xff+1):
file = open('./inp/overflow10000','wb')
file.write("a".encode()*10000)