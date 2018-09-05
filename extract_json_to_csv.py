#-*- coding: utf-8 -*-

import json
import pandas as pd
import multiprocessing as mp
import os
import sys

columns = ['sha256','sha1','md5','type','scan_date','positives','Bkav','ahnlab','TotalDefense','MicroWorld-eScan','nProtect','CMC','CAT-QuickHeal',\
           'eTrust-Vet','McAfee','Malwarebytes','VIPRE','Prevx','Paloalto','TheHacker','BitDefender','K7GW','K7AntiVirus','Invincea',\
           'Baidu','Agnitum','F-Prot','SymantecMobileInsight','Symantec','Norman','ESET-NOD32','TrendMicro-HouseCall','Avast','eSafe',\
           'ClamAV','Kaspersky','Alibaba','NANO-Antivirus','ViRobot','AegisLab','ByteHero','Rising','Ad-Aware','Trustlook','Sophos',\
           'Comodo','F-Secure','DrWeb','Zillya','AntiVir','TrendMicro','McAfee-GW-Edition','NOD32','VirusBuster','Emsisoft','SentinelOne',\
           'Cyren','Jiangmin','Webroot','Avira','PCTools','Fortinet','Antiy-AVL','Kingsoft','Endgame','Arcabit','SUPERAntiSpyware',\
           'ZoneAlarm','Avast-Mobile','Microsoft','Commtouch','AhnLab-V3','ALYac','AVware','MAX','VBA32','Cylance','WhiteArmor',\
           'Baidu-International','eScan','Zoner','Tencent','Yandex','Ikarus','eGambit','GData','AVG','Cybereason','Panda','CrowdStrike',\
           'Qihoo-360']

def write_csv(dict_csv,file_path):

    try:
        prex = dict_csv['sha256'][0][:3]
    except Exception,e:
    	print e
    	
    #file_path = "{0}/{1}/{2}/{3}/{4}".format(path_benhd, prex[0],prex[1],prex[2],'vt_report.csv')
    df = pd.DataFrame(dict_csv, columns = columns)
    if os.path.exists(file_path):
        df.to_csv(file_path, index=False, sep=',', mode='a', header=False, columns = columns)
    else:
        df.to_csv(file_path, index=False, sep=',', mode='a', columns = columns) 

def extract(file_name):

    malware_res = []
    benign_res = []

    json_file=open(file_name,'r')
    temp=json.load(json_file)
    json_file.close()
    #print json_data
    for each in temp:
        if not each:
          continue
        label_flag=0
        dict_csv = {'sha256':[],'sha1':[],'md5':[],'type':[],'scan_date':[],'positives':[],'ahnlab':[],'TotalDefense':[],'MicroWorld-eScan':[],'nProtect':[],\
                  'CMC':[],'CAT-QuickHeal':[],'eTrust-Vet':[],'McAfee':[],'Malwarebytes':[],'VIPRE':[],'Prevx':[],'Paloalto':[],'TheHacker':[],\
                  'BitDefender':[],'K7GW':[],'K7AntiVirus':[],'Invincea':[],'Baidu':[],'Agnitum':[],'F-Prot':[],'SymantecMobileInsight':[],'Symantec':[],\
                  'Norman':[],'ESET-NOD32':[],'TrendMicro-HouseCall':[],'Avast':[],'eSafe':[],'ClamAV':[],'Kaspersky':[],'Alibaba':[],'NANO-Antivirus':[],\
                  'ViRobot':[],'AegisLab':[],'ByteHero':[],'Rising':[],'Ad-Aware':[],'Trustlook':[],'Sophos':[],'Comodo':[],'F-Secure':[],'DrWeb':[],\
                  'Zillya':[],'AntiVir':[],'TrendMicro':[],'McAfee-GW-Edition':[],'NOD32':[],'VirusBuster':[],'Emsisoft':[],'SentinelOne':[],'Cyren':[],\
           	'Jiangmin':[],'Webroot':[],'Avira':[],'PCTools':[],'Fortinet':[],'Antiy-AVL':[],'Kingsoft':[],'Endgame':[],'Arcabit':[],'SUPERAntiSpyware':[],\
                  'ZoneAlarm':[],'Avast-Mobile':[],'Microsoft':[],'Commtouch':[],'AhnLab-V3':[],'ALYac':[],'AVware':[],'MAX':[],'VBA32':[],'Cylance':[],\
                  'WhiteArmor':[],'Baidu-International':[],'eScan':[],'Zoner':[],'Tencent':[],'Yandex':[],'Ikarus':[],'eGambit':[],'GData':[],'AVG':[],\
            'Cybereason':[],'Panda':[],'CrowdStrike':[],'Qihoo-360':[],'Bkav':[]}
        try:
            dict_csv['sha256'].append(temp[each]['sha256'])                              
            dict_csv['sha1'].append(temp[each]['sha1'])                                 
            dict_csv['md5'].append(temp[each]['md5'])                                    
            dict_csv['scan_date'].append(temp[each]['scan_date'])                        
            dict_csv['positives'].append(temp[each]['positives'])
            dict_csv['type'].append('exe/html')
            for i in columns[6:]:
                if i in temp[each]['scans'].keys():
                    if temp[each]['scans'][i]['result'] == None:
                        dict_csv[i].append(' ')
                    else:
                        label_flag=1
                        dict_csv[i].append(temp[each]['scans'][i]['result'])
                else:
                    dict_csv[i].append(' ')
        except Exception,e:
            print temp[each]
            print e
        if label_flag==0:
            benign_res.append(dict_csv)
        else:
            malware_res.append(dict_csv)
    prex=file_name.split('.')[0]
    for each in malware_res:
        write_csv(each,"m"+prex+".csv")
    for each in benign_res:
        write_csv(each,"b"+prex+".csv")

def process():
  base_dir='/data/result/'
  json_files=os.listdir(base_dir)
  for each in json_files:
    extract(base_dir+each)

  
if __name__=='__main__':
	main()