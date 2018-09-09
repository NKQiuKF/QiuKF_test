#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Nankai University Information Security
#QiuKF 1055419050@qq.com
#move files from failed folder into malware three levels
#The script is the frame of transport samples by multiprocess

from multiprocessing import Process,Pool
import os
import pandas as pd
import time
import sys

SAMPLES_PATH='/data/failed/'
CORRECT_PATH='/data/malware/'

#samples_path='/data/malware/collection/'



def main():

  samples=os.listdir(SAMPLES_PATH)
  for each_sample in samples:
    dst=CORRECT_PATH+each_sample[0]+'/'+each_sample[1]+'/'+each_sample[2]+'/'
    cmd_str='mv '+SAMPLES_PATH+each_sample+' '+dst
    print cmd_str
    os.popen(cmd_str)

if __name__=='__main__':
  main()


                                           
