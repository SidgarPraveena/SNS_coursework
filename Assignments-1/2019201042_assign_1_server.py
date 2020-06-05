#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import socket  
import pickle
import random
import os.path
import os
import _thread
from dataclasses import dataclass

@dataclass
class pubKey:
    P: int=0
    G: int=0
    key: int=0
        
@dataclass
class header:
    opcode: int=0
    src_file: str=""
    dest_file: str=""
    
class DiffieHellman:
    def getKey(self,G,a,P): #calculates a power G mod p
        if(G == 1):
            return a
        return ((pow(G, a)) % P)

    
class DESEncryption:
    def permutedChoice1(self,key):
        result=""
        pc1=[57, 49, 41, 33, 25, 17, 9,
               1,   58,    50,   42,    34,    26,   18,
              10,    2,    59,   51,    43,    35,   27,
              19,   11,     3,   60,    52,    44,   36,
              63,   55,    47,   39,    31,    23,   15,
               7,   62,    54,   46,    38,    30,   22,
              14,    6,    61,   53,    45,    37,   29,
              21,   13,     5,   28,    20,    12,    4]
        
        for i in range(0,56):
            result=result+key[pc1[i]-1]
        return result
    
    def initial_permutation(self, plain_text):
        initial_per=[58,50,42,34,26,18,10,2,
                    60,52,44,36,28,20,12,4,
                    62,54,46,38,30,22,14,6,
                    64,56,48,40,32,24,16,8,
                    57,49,41,33,25,17,9,1,
                    59,51,43,35,27,19,11,3,
                    61,53,45,37,29,21,13,5,
                    63,55,47,39,31,23,15,7]
        result=""
        for i in range(0,64):
            result=result+plain_text[initial_per[i]-1]
        return result
    
    def get_right_plain_text(self, plain_text):
        result=""
        result=plain_text[32:64]
        #print(len(result))
        return result
    
    def get_left_plain_text(self, plain_text):
        result=""
        result=plain_text[0:32]
        return result
    
    def expand_right_plain_text(self, plain_text):
        result=""
        e_box=[32,1,2,3,4,5,
               4,5,6,7,8,9,
               8,9,10,11,12,13,
               12,13,14,15,16,17,
               16,17,18,19,20,21,
               20,21,22,23,24,25,
               24,25,26,27,28,29,
               28,29,30,31,32,1]
        for i in range(0,48):
            result=result+plain_text[e_box[i]-1]
        return result
    
    def break_key(self,key):
        l_key=key[0:28]
        r_key=key[28:56]
        return l_key,r_key
    
    def shift_key(self,key, round_shift, round_num):
        r=round_shift[round_num]
        for i in range(0,r):
            b=key[0]
            key=key[1:28]
            key=key+b
        return key
    
    def xor_text_key(self, plain_text, key):
        result=""
        for i in range(0,len(plain_text)):
            p=int(plain_text[i])
            k=int(key[i])
            x=p^k
            result=result+str(x)
        return result
    
    def binaryToDecimal(self,binary): 
        binary1 = binary 
        decimal, i, n = 0, 0, 0
        while(binary != 0): 
            dec = binary % 10
            decimal = decimal + dec * pow(2, i) 
            binary = binary//10
            i += 1
        return decimal 
    
    def decimalToBinary(self,n): 
        return bin(n).replace("0b","")
    
    def get_s_box(self,text,index):
        result=""
        sbox = [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
             0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
             4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
             15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
             3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
             0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
             13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
             13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
             13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
             1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
             13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
             10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
             3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
             14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
             4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
             11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
             10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
             9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
             4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
             13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
             1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
             6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
             1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
             7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
             2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],]
        
        col=text[1:5]
        row=text[0]+text[5]
        col_decimal=self.binaryToDecimal(int(col))
        row_decimal=self.binaryToDecimal(int(row))
        s_box_index=row_decimal*16+col_decimal
        result=self.decimalToBinary(sbox[index][s_box_index])
        if len(result) == 3:
            result="0"+result
        elif len(result) == 2:
            result="00"+result
        elif(len(result) == 1):
            result="000"+result
        return result
    
    def s_box_compression(self, plain_text):
        index1=0
        index2=6
        result=""
        for i in range(0,8):
            text=plain_text[index1:index2]
            result=result+self.get_s_box(text,i)
            index1=index2
            index2=index2+6
        return result
    
    def round_permutation(self, plain_text):
        r_permutation=[16,7,20,21,29,12,28,17,
                      1,15,23,26,5,18,31,10,
                      2,8,24,14,32,27,3,9,
                      19,13,30,6,22,11,4,25]
        result=""
        for i in range(0,32):
            result=result+plain_text[r_permutation[i]-1]
        return result
    
    def permuted_choice2(self, key):
        result=""
        pc2=[14,    17,   11,    24 ,    1,    5,
                  3,    28,   15,     6,    21,   10,
                 23,    19,   12,     4,    26,    8,
                 16,     7,   27,    20,    13,    2,
                 41,    52,   31,    37,    47,   55,
                 30,    40,   51,    45,    33,   48,
                 44,    49,   39,    56,    34,   53,
                 46,    42,   50,    36,    29,   32]
        for i in range(0,48):
            result=result+key[pc2[i]-1]
        return result
            
    def roundFunction(self,plain_text, key, round_shift, round_num):
        left_plain_text=self.get_left_plain_text(plain_text)
        right_plain_text=self.get_right_plain_text(plain_text)
        expanded_plain_text=self.expand_right_plain_text(right_plain_text)
        left_key, right_key=self.break_key(key)
        shifted_left_key=self.shift_key(left_key,round_shift, round_num)
        shifted_right_key=self.shift_key(right_key,round_shift, round_num)
        shifted_key=shifted_left_key+shifted_right_key
        key_pc2=self.permuted_choice2(shifted_key)
        xor_plain_text=self.xor_text_key(expanded_plain_text,key_pc2)
        compressed_plain_text=self.s_box_compression(xor_plain_text)
        permuted_plain_text=self.round_permutation(compressed_plain_text)
        right_encrypted_text=self.xor_text_key(left_plain_text, permuted_plain_text)
        left_encrypted_text=right_plain_text
        encrypted_text=left_encrypted_text+right_encrypted_text
        return encrypted_text, shifted_key, key_pc2
 
    def rounds(self,plain_text, key,round_shift):
        for i in range(0, 16):
            plain_text,key,k=self.roundFunction(plain_text, key, round_shift, i)
        return plain_text,key
    
    def final_permutation(self,plain_text):
        final_permutation=[40,8,48,16,56,24,64,32,
                          39,7,47,15,55,23,63,31,
                          38,6,46,14,54,22,62,30,
                          37,5,45,13,53,21,61,29,
                          36,4,44,12,52,20,60,28,
                          35,3,43,11,51,19,59,27,
                          34,2,42,10,50,18,58,26,
                          33,1,41,9,49,17,57,25]
        result=""
        for i in range(0, len(plain_text)):
            result=result+plain_text[final_permutation[i]-1]
        return result    
    

class DESDecryption:
    def initial_permutation(self, plain_text):
        initial_per=[58,50,42,34,26,18,10,2,
                    60,52,44,36,28,20,12,4,
                    62,54,46,38,30,22,14,6,
                    64,56,48,40,32,24,16,8,
                    57,49,41,33,25,17,9,1,
                    59,51,43,35,27,19,11,3,
                    61,53,45,37,29,21,13,5,
                    63,55,47,39,31,23,15,7]
        result=""
        for i in range(0,64):
            result=result+plain_text[initial_per[i]-1]
        return result
    
    def get_right_text(self, plain_text):
        result=""
        result=plain_text[32:64]
        return result
    
    def get_left_text(self, plain_text):
        result=""
        result=plain_text[0:32]
        return result
    
    def expand_right_text(self, plain_text):
        result=""
        e_box=[32,1,2,3,4,5,
               4,5,6,7,8,9,
               8,9,10,11,12,13,
               12,13,14,15,16,17,
               16,17,18,19,20,21,
               20,21,22,23,24,25,
               24,25,26,27,28,29,
               28,29,30,31,32,1]
        for i in range(0,48):
            result=result+plain_text[e_box[i]-1]
        return result
    
    def xor_text_key(self, plain_text, key):
        result=""
        for i in range(0,len(plain_text)):
            p=int(plain_text[i])
            k=int(key[i])
            x=p^k
            result=result+str(x)
        return result
    
    def binaryToDecimal(self,binary): 
        binary1 = binary 
        decimal, i, n = 0, 0, 0
        while(binary != 0): 
            dec = binary % 10
            decimal = decimal + dec * pow(2, i) 
            binary = binary//10
            i += 1
        return decimal 
    
    def decimalToBinary(self,n): 
        return bin(n).replace("0b","")
    
    def get_s_box(self,text,index):
        result=""
        sbox = [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
             0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
             4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
             15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
             3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
             0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
             13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
             13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
             13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
             1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
             13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
             10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
             3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
             14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
             4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
             11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
             10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
             9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
             4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
             13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
             1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
             6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
             1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
             7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
             2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],]
        
        col=text[1:5]
        row=text[0]+text[5]
        col_decimal=self.binaryToDecimal(int(col))
        row_decimal=self.binaryToDecimal(int(row))
        s_box_index=row_decimal*16+col_decimal
        result=self.decimalToBinary(sbox[index][s_box_index])
        if len(result) == 3:
            result="0"+result
        elif len(result) == 2:
            result="00"+result
        elif(len(result) == 1):
            result="000"+result
        return result
    
    def s_box_compression(self, plain_text):
        index1=0
        index2=6
        #print(plain_text)
        result=""
        for i in range(0,8):
            text=plain_text[index1:index2]
            result=result+self.get_s_box(text,i)
            index1=index2
            index2=index2+6
        return result
    
    def round_permutation(self, plain_text):
        r_permutation=[16,7,20,21,29,12,28,17,
                      1,15,23,26,5,18,31,10,
                      2,8,24,14,32,27,3,9,
                      19,13,30,6,22,11,4,25]
        result=""
        for i in range(0,32):
            result=result+plain_text[r_permutation[i]-1]
        return result
    
    def break_key(self,key):
        l_key=key[0:28]
        r_key=key[28:56]
        return l_key,r_key
    
    def shift_key(self,key, round_shift, round_num):
        r=round_shift[round_num]
        for i in range(0,r):
            b=key[27]
            key=key[0:27]
            key=b+key
        return key
    
    def permuted_choice2(self, key):
        result=""
        pc2=[14,    17,   11,    24 ,    1,    5,
                  3,    28,   15,     6,    21,   10,
                 23,    19,   12,     4,    26,    8,
                 16,     7,   27,    20,    13,    2,
                 41,    52,   31,    37,    47,   55,
                 30,    40,   51,    45,    33,   48,
                 44,    49,   39,    56,    34,   53,
                 46,    42,   50,    36,    29,   32]
        for i in range(0,48):
            result=result+key[pc2[i]-1]
        return result
    
    def roundFunction(self,e_text, key,round_shift, round_num):
        #print(len(e_text))
        left_text=self.get_left_text(e_text)
        right_text=self.get_right_text(e_text)
        expanded_text=self.expand_right_text(right_text)
        key_pc2=self.permuted_choice2(key)
        left_key, right_key=self.break_key(key)
        shifted_key=""
        shifted_left_key=self.shift_key(left_key,round_shift, round_num)
        shifted_right_key=self.shift_key(right_key,round_shift, round_num)
        shifted_key=shifted_left_key+shifted_right_key
        
        xor_text=self.xor_text_key(expanded_text,key_pc2)
        compressed_text=self.s_box_compression(xor_text)
        permuted_text=self.round_permutation(compressed_text)
        right_d_text=self.xor_text_key(left_text, permuted_text)
        left_d_text=right_text
        
        d_text=left_d_text+right_d_text
        return d_text, shifted_key, key_pc2
    
    def rounds(self,e_text, key, round_shift):
        for i in range(0, 16):
            e_text,key,k=self.roundFunction(e_text,key, round_shift,i)
        return e_text,key
    
    def final_permutation(self,plain_text):
        final_permutation=[40,8,48,16,56,24,64,32,
                          39,7,47,15,55,23,63,31,
                          38,6,46,14,54,22,62,30,
                          37,5,45,13,53,21,61,29,
                          36,4,44,12,52,20,60,28,
                          35,3,43,11,51,19,59,27,
                          34,2,42,10,50,18,58,26,
                          33,1,41,9,49,17,57,25]
        result=""
        for i in range(0, len(plain_text)):
            result=result+plain_text[final_permutation[i]-1]
        return result
    
def threeDesEncryption(k1,k2,k3,plain_text):
    enc_obj=DESEncryption()
    dec_obj=DESDecryption()
    
    k1_pc=enc_obj.permutedChoice1(k1)
    k2_pc=enc_obj.permutedChoice1(k2)
    k3_pc=enc_obj.permutedChoice1(k3)
    round_shift=[1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    round_shift_d=[1,2,2,2,2,2,2,1,2,2,2,2,2,2,1,1]

    #step1: encryption 
    pt1_permutation=enc_obj.initial_permutation(plain_text)
    r_t1,r_k1=enc_obj.rounds(pt1_permutation, k1_pc, round_shift)
    s_r_t1=r_t1[32:64]
    s_r_t1=s_r_t1+r_t1[0:32]
    e_t_1=enc_obj.final_permutation(s_r_t1)
    #print(e_t_1)

    #step2: decryption 
    pt2_permutation=dec_obj.initial_permutation(e_t_1)
    r_t2,r_k2=dec_obj.rounds(pt2_permutation, k2_pc, round_shift_d)
    s_r_t2=r_t2[32:64]
    s_r_t2=s_r_t2+r_t2[0:32]
    d_t_2=dec_obj.final_permutation(s_r_t2)
    #print(d_t_2)

    #step3: encryption
    pt3_permutation=enc_obj.initial_permutation(d_t_2)
    r_t3,r_k3=enc_obj.rounds(pt3_permutation, k3_pc, round_shift)
    s_r_t3=r_t3[32:64]
    s_r_t3=s_r_t3+r_t3[0:32]
    e_t_3=enc_obj.final_permutation(s_r_t3)

    #print("Encrypted text ", end=" ")
    #print(e_t_3)
    return e_t_3
        
    
class DES:
    def to_binary(self, s):
        s_decoded=s.decode("utf-8")
        res=""
        for i in s:
            r=format(ord(chr(i)), 'b')
            if len(r)<8:
                r=r.rjust(8,"0")
            res=res+r
        return res

    def breakAddPadd(self,l,k1,k2,k3):
        res=""
        if len(l) <128:
            l+=bytes(128-len(l))
        i_1=0
        i_2=8
        while i_2<=128:
            sub_str=l[i_1: i_2]
            binary_str=self.to_binary(sub_str)
            
            #print(type(binary_str),end=" ")
            #print(binary_str)
            #3DES encoding is done here
            binary_str=threeDesEncryption(k1,k2,k3,binary_str)
            #print(binary_str)
            #print(type(binary_str1))
            
            res=res+binary_str
            i_1=i_2
            i_2=i_2+8
        return res

def to_binary(k):
    result=""
    key=str(k)
    for i in key:
        r=format(ord(i), 'b')
        r='00'+r
        result=result+r
    return result

def on_new_client(clientsocket,addr):
    obj=DiffieHellman()

    # For 1st key 

    data_variable=clientsocket.recv(1024)
    res= pickle.loads(data_variable)
    privateKey1=random.randrange(0,res.P)

    key1 = obj.getKey(res.key,privateKey1, res.P)

    k1=pubKey(res.P, res.G)
    k1.key=obj.getKey(k1.G, privateKey1, k1.P)

    data_string = pickle.dumps(k1)
    clientsocket.sendall(data_string)

    #print("Key 1 {}".format(key1))
    #print(to_binary(key1))

    # For 2nd key

    data_variable=clientsocket.recv(1024)
    res= pickle.loads(data_variable)
    privateKey2=random.randrange(0,res.P)

    key2 = obj.getKey(res.key,privateKey2, res.P)

    k2=pubKey(res.P, res.G)
    k2.key=obj.getKey(k2.G, privateKey2, k2.P)

    data_string = pickle.dumps(k2)
    clientsocket.sendall(data_string)

    #print("Key 2 {}".format(key2))
    #print(to_binary(key2))

    # For 3rd key

    data_variable=clientsocket.recv(1024)
    res= pickle.loads(data_variable)
    privateKey3=random.randrange(0,res.P)

    key3 = obj.getKey(res.key,privateKey3, res.P)

    k3=pubKey(res.P, res.G)
    k3.key=obj.getKey(k3.G, privateKey3, k3.P)

    data_string = pickle.dumps(k3)
    clientsocket.sendall(data_string)

    #print("Key 3 {}".format(key3))
    #print(to_binary(key3))

    k1_="0001001100110100010101110111100110011011101111001101111111110001"
    k2_="0100101010001010100010010010001110100010000100001001000001011100"
    k3_="0100101000111010101110101010100010101011110100101010101010101001"

    req_file=clientsocket.recv(1024)
    reqServ=pickle.loads(req_file)
    print("Request received from {}".format(addr[1]))

    if os.path.isfile(reqServ.src_file):  #if file exist
        print("File exist")
        reply_request=header(3,reqServ.src_file, reqServ.dest_file)
        replyReq=pickle.dumps(reply_request)
        clientsocket.sendall(replyReq)

        #sending file size
        file_status=os.stat(reqServ.src_file)
        clientsocket.sendall(str(file_status.st_size).encode("utf-8"))

        des_obj=DES()

        f=open(reqServ.src_file, "rb")
        l=f.read(128)
        while(l):
            binary_l=des_obj.breakAddPadd(l,k1_,k2_,k3_)
            clientsocket.sendall(binary_l.encode("utf-8"))
            l=f.read(128)
        f.close()
        print("File is transmitted to {}".format(addr[1]))
        print("connection is closing with {}".format(addr[1]))



    else: #if there is no file
        print("File {} do not exist".format(reqServ.src_file))
        reply_request=header(2,reqServ.src_file, reqServ.dest_file)
        replyReq=pickle.dumps(reply_request)
        clientsocket.sendall(replyReq)
    clientsocket.close()
    
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
host = socket.gethostname()                           
port = 9999                                           
serversocket.bind((host, port)) 
serversocket.listen(5)                                           

while True:
    clientsocket,addr = serversocket.accept() 
    _thread.start_new_thread(on_new_client,(clientsocket,addr))
    
serversocket.close()


# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:




