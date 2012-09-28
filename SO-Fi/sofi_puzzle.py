"""
Client-Puzzle Library for So-Fi

    :copyright: (c) Copyright 2012 by Benjamin Grap.
    :license: BSD, see LICENSE for more details.
"""

import hashlib
import random
import struct
import time
import binascii
import logging

from sofi_timing import *
import sofi_crypt

class k_zero_puzzle():
    
    
    def createPuzzle(self,puzzleSize=20):
        try:
            randgen = random.SystemRandom()
        except:
            randgen = random
        
        b = bytearray()
        for _i in xrange(puzzleSize):
            b.append(randgen.randint(0,255))
        return b
    
    def solvePuzzle(self, puzzle, bitSize=1):
        i = 1
        while(not self._isSolution(puzzle, i, bitSize)):
            i = i + 1
        return i
        
    
    def _isSolution(self, puzzle, solution, size):
        
        sol = bytearray(hashlib.sha1("%s%s"%(puzzle,self._bytes(solution))).digest())
        #print hashlib.sha1("%s%s"%(puzzle,self._bytes(solution))).hexdigest()
        _i = 0
        while(sol[_i / 8]&(2**(7-(_i%8)))!=(2**(7-(_i%8)))):
            #print _i, sol[_i / 8]&(2**(7-(_i%8))), (2**(7-(_i%8))), sol[_i / 8]&(2**(7-(_i%8)))!=(2**(7-(_i%8))), sol[_i/8]
            _i=_i+1
            
        return (_i>=size)
    
    def _bytes(self, data ):
        return struct.pack('L',data)

class mk_preimage_puzzle():
    def __init__(self):
        self.count=0
    
    def createPuzzle(self,preimageSize=4):
        self.count=0
        if(preimageSize>20):
            return None
        try:
            randgen = random.SystemRandom()
        except:
            randgen = random
        
        b = bytearray()
        for _i in xrange(preimageSize):
            b.append(randgen.randint(0,255))
            
        s = hashlib.sha1("%s" %b).digest()
        z = bytearray(struct.pack('>18sH',s[0:18],sofi_crypt.crc16(s[0:18])))
        return z

    def isValidPuzzle(self,puzzle):
        puzzle = "%s" %puzzle
        crc1 = sofi_crypt.crc16(puzzle[0:18])
        crc2, = struct.unpack('>H',puzzle[18:20])
        if(crc1 == crc2):
            return True
        else:
            return False

    def solveSubPuzzleInc(self, puzzle, subNo, bitSize):
        i = 0
        sol = bytearray([0,0,0,0])
        while(not self._isSolution(puzzle, subNo, sol, bitSize)):
            i = i + 1
            #print [((i/(2**24))%256),((i/(2**16))%256),((i/(2**8))%256),(i%256)]
            sol = bytearray([((i/(2**24))%8),((i/(2**16))%8),((i/(2**8))%8),(i%8)])
        return sol
    
    def solveSubPuzzle(self, puzzle, subNo, bitSize):
        return self.solveSubPuzzleRnd(puzzle,subNo,bitSize)
        #return self.solveSubPuzzleInc(puzzle,subNo,bitSize)
    
    def solveSubPuzzleRnd(self,puzzle,subNo,bitSize):
        sol = bytearray([0,0,0,0])
        while(not self._isSolution(puzzle, subNo, sol, bitSize)):
            sol = bytearray()
            for _i in xrange(4):
                sol.append(random.randint(0,255))
        return sol
    
    def solvePuzzle(self, puzzle, subNo=5, bitSize=5):
        if(subNo>255 or bitSize>(len(puzzle)*8)):
            return None
        solutions = []
        for i in xrange(subNo):
            solutions.append(self.solveSubPuzzle(puzzle,i,bitSize))
        return solutions
    
    def solvePuzzleS(self, puzzle, subNo=5, bitSize=5):
        solutions = self.solvePuzzle(puzzle,subNo=subNo,bitSize=bitSize)
        logging.info("Solution list: %s" %solutions)
        sol = ""
        for item in solutions:
            sol = sol + str(item)
        return sol
    
    def _isSolution(self, puzzle, subNo, solution, bitSize):
        puz = bytearray(puzzle)
        sol = bytearray(hashlib.sha1("%s%s%s"%(puzzle,bytearray([subNo]),solution)).digest())
        self.count += 1
        #print hashlib.sha1("%s%s"%(puzzle,self._bytes(solution))).hexdigest()
        #print binascii.hexlify(sol)
        _i = 0
        while(sol[_i / 8]&(2**(7-(_i%8)))==puz[_i / 8]&(2**(7-(_i%8)))):
            #print _i, sol[_i / 8]&(2**(7-(_i%8))), (2**(7-(_i%8))), sol[_i / 8]&(2**(7-(_i%8)))!=(2**(7-(_i%8))), sol[_i/8]
            _i=_i+1    
        return (_i>=bitSize)
    
    def _checkSolution(self, puzzle, subNo, solution, bitSize):
        puz = bytearray(puzzle)
        sol = bytearray(hashlib.sha1("%s%s%s"%(puzzle,bytearray([subNo]),solution)).digest())
        #print hashlib.sha1("%s%s"%(puzzle,self._bytes(solution))).hexdigest()
        #print binascii.hexlify(sol)
        _i = 0
        while(sol[_i / 8]&(2**(7-(_i%8)))==puz[_i / 8]&(2**(7-(_i%8)))):
            #print _i, sol[_i / 8]&(2**(7-(_i%8))), (2**(7-(_i%8))), sol[_i / 8]&(2**(7-(_i%8)))!=(2**(7-(_i%8))), sol[_i/8]
            _i=_i+1
            
        return (_i>=bitSize)
    
    @print_timing
    def verifyPuzzle(self,puzzle,solution,subSize=5,bitSize=5):
        for i in xrange(subSize):
            if(not self._checkSolution(puzzle,i,solution[i],bitSize)):
                return False
        return True
    
    @print_timing
    def verifyPuzzleS(self,puzzle,solution,subSize=5,bitSize=5):
        if(len(solution)<20):
            logging.error("Solution Size was below 20 Bytes!")
            return False
        else:
            sol = []
            for i in xrange(1,6):
                sol.append(bytearray(solution[((i-1)*4):(i*4)]))
            logging.info("Puzzle is listed as: %s" %sol)
            return self.verifyPuzzle(puzzle,sol,subSize=subSize,bitSize=bitSize)
            
    def getCount(self):
        return self.count
        

"""
Define some Tests for the Puzzle Functions.
"""

def test1():
    p = mk_preimage_puzzle()
    for i in range(24):
        elapsed=[]
        for _j in range(10):
            puzzle = p.createPuzzle(4)
            print puzzle
            elapsed.append(time_solve(p,puzzle,i))
        
        print "Searching for %s :" %i, elapsed
        
 
def test2():
    bitSize = 5
    subNo = 5
    p = mk_preimage_puzzle()
    puzzle = p.createPuzzle()
    print binascii.hexlify(puzzle)
    print puzzle
    puzzle = str(puzzle)
    solution =  p.solvePuzzleS(puzzle,bitSize=bitSize)
    print solution
    #print solution
    print "Number of Hashes Computed: %i" %p.getCount()
    print "Verifying solution: %s" %p.verifyPuzzleS(puzzle, solution)#, subNo, bitSize)
   
def test3(bitSize=1):
    p = mk_preimage_puzzle()
    sampleSize = 10
    for bitSize in xrange(1,17):
        hashComputations= []
        hashCompTime = []
        for _i in xrange(sampleSize):
            puzzle = p.createPuzzle(4)
            start = time.clock()
            solution = p.solvePuzzle(puzzle,bitSize=bitSize)
            #print p.verifyPuzzle(puzzle, solution)
            hashCompTime.append(time.clock()-start)
            hashComputations.append(p.getCount())
        
        avg = 0
        avgTime = 0 
        for _i in range(sampleSize):
            avg = avg + hashComputations[_i]
            avgTime = avgTime + hashCompTime[_i] 
       
        print "BitSize: %s" %bitSize
        print hashComputations, hashCompTime
        print avg / float(sampleSize)
        print avgTime / float(sampleSize)


def test4():
    start = time.clock()
    for _i in xrange(211912):
        hashlib.sha1("%s%s%s"%("test",bytearray([_i%256]),"blah")).digest()
    print "Calculating 211912 Hashes took: %.06f"%(time.clock()-start)

def eval_puzzle():
    import time
    import csv
    import platform
    
    sampleSize = 1000
    writer = csv.writer(open("puzzles_" + platform.system() +"_"+ platform.node() +"_"+ platform.release()+ "_" + platform.processor() + ".csv","ab"))
    
    p = mk_preimage_puzzle()
    for bitSize in xrange(1,17):
        hashComputations= [bitSize]
        hashCompTime = [bitSize]
        for _i in xrange(sampleSize):
            puzzle = p.createPuzzle(4)
            start = time.time()
            solution = p.solvePuzzle(puzzle,bitSize=bitSize)
            #print p.verifyPuzzle(puzzle, solution)
            hashCompTime.append(time.time()-start)
            hashComputations.append(p.getCount())
        writer.writerow(hashComputations)
        writer.writerow(hashCompTime)
   


def time_solve(p,mypuzzle,i):
    start = time.clock()
    #print p.solvePuzzle(mypuzzle,size=i)
    p.solvePuzzle(mypuzzle,bitSize=i)
    return (time.clock() - start)

def main():
    test3()


if __name__ == "__main__":
    main()
