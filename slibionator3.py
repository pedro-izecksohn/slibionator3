#!/usr/bin/python3

about = '''slibionator2 - A cryptography application.
slibionator means 'sliding bits on a torus'.
By: Pedro Izecksohn
Version: 2023-Jul-20 21:57
License: This is free software.'''

import random

def ifc (x, y):
  #print 'ifc (x =',x, ', y =',y, ')'
  if  x == -1: x = 7
  elif x == 8: x = 0
  if  y == -1: y = 7
  elif y == 8: y = 0
  return (y*8)+x

class XY:
  def __init__ (self, x, y):
    self.x = x
    self.y = y
  @staticmethod
  def from_ifc (i):
    return XY ((i&7), (i>>3))
  def set_ifc (self, i):
    self.x = i & 7
    self.y = i >> 3
  def ifc (self):
    return ifc (self.x, self.y)
  def __str__ (self):
    return '('+str(self.x)+', '+str(self.y)+')'

'''
As block is a copy, not a pointer, you must set it yourself with the result
of this function.
'''
def block_set_bit (block, i, bit):
  #print 'block_set_bit ('+hex(block)+', '+str(i)+', '+str(bit)+')'
  assert block < 2**64
  assert i > -1
  assert i < 64
  assert bit > -1
  assert bit < 2
  t = 1 << i
  if bit==0:
    t = ~t
    block &= t
  else: block |= t
  #print 'block = '+hex(block)
  return block

def block_get_bit (quadword, i):
  assert quadword < 2**64
  assert i > -1
  assert i < 64
  return (quadword >> i) & 1

def not_password (pw):
  #print("pw="+str(pw))
  l=[]
  for c in pw:
    assert 0 <= c < 4
    if    c==0: c=3
    elif c==3: c=0
    elif c==1: c=2
    elif c==2: c=1
    l.insert(0,c)
  #print("Returning "+str(l))
  return l

# Modifies cursor.
# Returns the new block.
def apply_command (cursor, block, command):
  #print ('apply_command ('+str(cursor)+', '+str(block)+', '+str(command)+')')
  assert block < 2**64
  assert command > -1
  assert command < 4
  if command == 0:
    oi = ifc (cursor.x, cursor.y+1)
  elif command == 3:
    oi = ifc (cursor.x, cursor.y-1)
  elif command == 1:
    oi = ifc (cursor.x+1, cursor.y)
  elif command == 2:
    oi = ifc (cursor.x-1, cursor.y)
  ci = cursor.ifc()
  tmpci = block_get_bit (block, ci)
  block = block_set_bit (block, ci, block_get_bit (block, oi))
  block = block_set_bit (block, oi, tmpci)
  #print 'block = '+hex(block)
  cursor.set_ifc (oi)
  return block

def print_square (block):
  assert block < 2**64
  line = ''
  for i in range(64):
    bit = block_get_bit (block, i)
    if len(line) == 8:
      print (line)
      line = str(bit)
    else:
      line = (line + str(bit))  
  print (line)

def decrypt (pw, ba):
  npw = not_password (pw)
  print("len(npw)="+str(len(npw)))
  ret=bytearray()
  cursor = XY.from_ifc (ba[-1])
  ba=ba[0:-1]
  nblocks=len(ba)//8
  if len(ba)%8:
      print("This cipher was not encrypted by this program.")
      exit()
  nblocks-=1
  while nblocks>-1:
      print("nblocks="+str(nblocks))
      bb=ba[nblocks*8:(nblocks+1)*8]
      i=int.from_bytes(bb,byteorder='little')
      for command in npw:
          #print("Before.")
          i=apply_command (cursor, i, command)
          #print("After.")
      bc=i.to_bytes(8,byteorder='little')
      for b in reversed(bc):
          ret.insert(0,b)
      nblocks-=1
  n=ret[0]&7
  ret=ret[n+1:]
  return ret

def encrypt (pw, ba):
  #print 'I\'m inside encrypt ('
  ret=bytearray()
  cursor = XY.from_ifc (random.randint(0,63))
  n = 8-(len(ba)%8)
  rba=bytearray()
  i=0
  while i<n:
      rba.append(random.randint(0,255))
      i+=1
  rba[0]=(rba[0]&0b11111000)|(n-1)
  rba.extend(ba)
  ba=rba
  nblocks=len(ba)//8
  print(f"nblocks={nblocks}")
  index=0
  while index<nblocks:
      bb=ba[index*8:(index+1)*8]
      i=int.from_bytes(bb,byteorder='little')
      for command in pw:
          i=apply_command (cursor, i, command)
      bc=i.to_bytes(8,byteorder='little')
      ret.extend(bc)
      index+=1 
  cursor_ifc = cursor.ifc()
  print("cursor_ifc="+str(cursor_ifc))
  ret.append (cursor_ifc)
  return ret

def password2bytes(password):
    ba=bytearray()
    i=0
    while i<len(password):
        if i<(len(password)-1):
            ba.append(int(password[i:i+2],16))
        else:
            ba.append(int(password[i],16))
        i+=1
    return ba

def xor (ba, bb):
    ret=bytearray()
    i=0
    for b in ba:
        ret.append(b^bb[i])
        i+=1
        if i==len(bb):
            i=0
    return ret

def ba2hex(ba):
    ret=""
    for i,b in enumerate(ba):
        ret+=hex(b)[2:]
        if i<(len(ba)-1):
            ret+=','
    return ret

def hex2ba(s):
    l=s.split(',')
    ba=bytearray()
    for i in l:
        ba.append(int(i,16))
    return ba

def main():
    password = input ("Enter the password: ")
    pw = []
    for h in password: # h represents 4 bits.
        i=int(h,16)
        pw.append ((i&12)>>2)
        pw.append (i&3)
    ifilename = input ("Enter the input filename: ")
    ofilename = input ("Enter the output filename: ")
    op = input ("Enter e to encrypt or d to decrypt: ").lower()
    if op=='e':
        file = open(ifilename,'rb')
        obj = file.read()
        #print (type(obj))
        file.close()
        ba = bytearray (obj)
        ba = encrypt (pw, ba)
        ba = xor (ba, password2bytes(password))
        ba[-1]=ba[-1]&63
        s=ba2hex(ba)
        file=open(ofilename,'x')
        file.write(s)
        file.close()
    elif op=='d':
        file = open(ifilename,'r')
        s = file.read()
        file.close()
        ba=hex2ba(s)
        ba = xor (ba, password2bytes(password))
        ba[-1]=ba[-1]&63
        ba = decrypt (pw, ba)
        file = open(ofilename,"xb")
        file.write (ba)
        file.close()
    else:
        print("Invalid operation.")
    print ('I\'m after the operation.')
    exit()

main()
