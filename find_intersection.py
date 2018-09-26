#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pandas as pd
#Nankai University Information Security
#QiuKF 1055419050@qq.com
#find intersection from all_labels and all_datas
def main():
  data_sha256=pd.read_csv('all_data.txt',names=['sha256'])
  benign_df=pd.read_csv('Total_File_Data(QiuKF).csv')
  #set([' ', 'positives', '1.0', '0', '0.0'])
  #filter ' '
  benign_df=benign_df[benign_df['positives']!=' ']
  #filter 'positives'
  benign_df=benign_df[benign_df['positives']!='positives']
  #filter '1.0'
  benign_df=benign_df[benign_df['positives']!='1.0']
  benign_label_sha256=benign_df['sha256']
  print 'positives0',len(list(benign_label_sha256))
  benign_list=set(list(benign_label_sha256))
  print len(benign_list)
  data_list=set(list(data_sha256['sha256']))
  print len(data_list)

  positives0=list(benign_list&data_list)
  print 'positives0,data',len(positives0)
  malware_df=pd.read_csv('Total_File_Data(malware).csv')
  tmp1=malware_df[malware_df['positives']=='1']
  tmp2=malware_df[malware_df['positives']=='1.0']
  positives1=list(tmp1['sha256'])+list(tmp2['sha256'])
  print 'positives1',len(positives1)

  #set(['42', '35.0', '52.0', '7.0', '12.0', 
  #'6.0', '37.0', '50.0', '24', ' ', '26', '27', '20', '21', 
  #'22', '23', '28', '29', '0', '4', '44.0', '16.0', '8', '45.0', 
  #'26.0', '14.0', '24.0', '22.0', '49.0', '54.0', '34.0', '3.0', '2.0',
  # '36.0', '20.0', '3', '7', '25', '40.0', '27.0', '42.0', '25.0', '39', 
  # '38', '33', '32', '31', '30', '37', '36', '35', '34', '23.0', '32.0', 
  # '60.0', '33.0', '19.0', '39.0', '8.0', '21.0', '2', '6', '9.0', '41.0', 
  # '28.0', '43.0', '11', '10', '13', '12', '15', '14', '17', '16', '19', '18', 
  # '31.0', '18.0', '1.0', '53.0', '30.0', '38.0', '51.0', '13.0', '5.0', '4.0', 
  # '48', '46', '44', '11.0', '43', '40', '41', '1', '17.0', '5', '9', '47.0', '46.0',
  #  'positives', '29.0', '15.0', '48.0', '10.0'])

  malware_df=malware_df[malware_df['positives']!=' ']
  malware_df=malware_df[malware_df['positives']!='0.0']
  malware_df=malware_df[malware_df['positives']!='0']
  malware_df=malware_df[malware_df['positives']!='1']
  malware_df=malware_df[malware_df['positives']!='1.0']
  malware_df=malware_df[malware_df['positives']!='positives']
  print 'positives2',len(list(malware_df['sha256']))
  malware_list=set(list(malware_df['sha256']))

  positives2=list(malware_list&data_list)

  out=open('positives0','w')
  out.writelines('\n'.join(positives0))
  out.close
  out=open('positives1','w')
  out.writelines('\n'.join(positives1))
  out.close
  out=open('positives2','w')
  out.writelines('\n'.join(positives2))
  out.close

if __name__ == '__main__':
  main()
