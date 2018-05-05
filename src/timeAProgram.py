# A program to time the execution of a java program
# in python.
# Copyright (R) 2016 - Dr. Rivas

import timeit
import os
import glob

SETUP = '''
import os
'''

for testCase in sorted(glob.glob('testcase.0')):
    testCaseTime = min(timeit.Timer('os.system("java Driver ' +
      '0304050001020607080415161718191a1b1c1d1e90a0b0c0d0e311f0f1011121 ' +
      'cddeeff001122335544667 0 > /dev/null 2>&1")', 
                   setup = SETUP).repeat(100,1))

    print(testCaseTime)

