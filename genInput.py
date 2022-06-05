from numpy import byte



out = ''
for b in range(0xff+1):
    file = open('./inp/'+str(b),'wb')
    file.write(chr(b).encode()*100)