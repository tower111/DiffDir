import logging

import ida2bindiff
import config
import json
import os
import shutil
import sqlite3
from tqdm import tqdm
def clean():
    shutil.rmtree(config.output1, ignore_errors=True)
    shutil.rmtree(config.output2, ignore_errors=True)  
    shutil.rmtree(config.tmp_dir, ignore_errors=True)  
    shutil.rmtree(config.bindiff_dir, ignore_errors=True)  
    os.mkdir(config.bindiff_dir)
    os.mkdir(config.tmp_dir)
def get_one():
    result1={}
    result2={}
    if os.path.exists(config.temp):
        with open(config.temp,"r") as fd:
            content=json.loads(fd.read())
        result1=content[0]
        result2=content[1]
    else:
        # logging.INFO("export source")
        for item in tqdm(ida2bindiff.main(config.input1,config.output1)):
            raw=item[0]
            binextra=item[1]
            result1[raw]=binextra
        # logging.INFO("export target")
        for item in tqdm(ida2bindiff.main(config.input2,config.output2)):
            raw=item[0]
            binextra=item[1]
            result2[raw]=binextra
        with open(config.temp,"w") as fd:
            fd.write(json.dumps([result1,result2]))
    aset=set()
    adict={}
    bset=set()
    bdict={}
    for key1,v1 in result1.items():
        base1=os.path.basename(v1)
        aset.add(base1)
        adict[base1]=key1
    for key2,v2 in result2.items():
        base2=os.path.basename(v2)
        bset.add(base2)
        bdict[base2]=key2
    only_old_file_list=[]
    for item in (aset-bset):
        if item in aset:
            only_old_file_list.append(adict[item])
        assert item in aset
    only_new_file_list=[]
    for item in (bset-aset):
        if item in bset:
            only_new_file_list.append(bdict[item])
        assert item in bset


    for key1,v1 in result1.items():
        for key2,v2 in result2.items():
            base1=os.path.basename(v1)
            base2=os.path.basename(v2)
            if base1==base2:
                diff_file=os.path.join(config.bindiff_dir,os.path.basename(v1)+"_vs_"+os.path.basename(v1)+".BinDiff")
                if os.path.exists(diff_file):
                    continue
                CMD="/usr/local/bin/bindiff --output_dir {} {} {}".format(config.bindiff_dir,
                                                           v1+"/"+os.path.basename(v1)+
                                                           ".BinExport",v2+"/"+os.path.basename(v2)
                                                           +".BinExport")
                os.system(CMD+"> /dev/null")
    show(save_sim_info(result1),only_old_file_list,only_new_file_list)

def save_sim_info(result1):
    result=[]
    for key1,v1 in result1.items():
        diff_file=os.path.join(config.bindiff_dir,os.path.basename(v1)+"_vs_"+os.path.basename(v1)+".BinDiff")
        # if os.path.exists(os.path. config.bindiff_dir)
    # for item in os.listdir(config.bindiff_dir):
    #     filename=os.path.join(config.bindiff_dir,item)
        differ=diff_sim(diff_file)
        if differ.is_notSim==True:
            tmp={}
            tmp["raw"]=key1
            tmp["diff_info"]=differ.not_sim
            result.append(tmp)
        

    with open(config.dif_result,"w") as fd:
        fd.write(json.dumps(result))
    return result


def show(result,only_old_file_list,only_new_file_list):
    save_string=""
    change_set=set()
    save_string+="only_old_file_list:\n"
    save_string+="\n".join(only_old_file_list)
    save_string+="\n\n"

    save_string+="only_new_file_list:\n"
    save_string+="\n".join(only_new_file_list)
    save_string+="\n\n\n"

    save_string+="changed file:\n"
    for change_file in result:
        change_set.add(change_file["raw"])
        # save_string+=change_file[]
    for item in change_set:
        save_string+=item+"\n"
    for index,item in enumerate(result):
        str_index=str(index)
        for funcinfo in item["diff_info"]:
            tmp_save_string=""
            tmp_save_string+=str_index+" "+"rawpath: "+item["raw"]+"\n"
            tmp_save_string+=str_index+" "+"id: "+str(funcinfo["id"])+"\n"
            tmp_save_string+=str_index+" "+"address1: "+str(funcinfo["address1"])+"\n"
            tmp_save_string+=str_index+" "+"name1: "+funcinfo["name1"]+"\n"
            tmp_save_string+=str_index+" "+"address2: "+str(funcinfo["address2"])+"\n"
            tmp_save_string+=str_index+" "+"name2: "+funcinfo["name2"]+"\n"
            tmp_save_string+=str_index+" "+"sim: "+str(funcinfo["sim"])+"\n\n\n"
            print(tmp_save_string)
            save_string+=tmp_save_string
    with open(config.dif_result_log,"w") as fd:
        fd.write(save_string)

        # print(index,"原始文件路径:",item["key"])
        # print(index,"id",item["diff_info"]["id"])
        # print(index,"address1",item["diff_info"]["address1"])
        # print(index,"name1",item["diff_info"]["name1"])
        # print(index,"address2",item["diff_info"]["address2"])
        # print(index,"name2",item["diff_info"]["name2"])
        # print(index,"sim",item["diff_info"]["sim"])

    

class diff_sim(list):
    def __init__(self,name) :
        self.name=name
        mydb=sqlite3.connect(self.name)
        self.cursor=mydb.cursor()
        self.not_sim=[]
        self.is_notSim=False
        self.get_sim_func()
    def get_sim_func(self):
        CMD="select *from function"
        self.cursor.execute(CMD)
        info=self.cursor.fetchall()
        for item in info:
            if item[5] == "":
                continue
            if item[5]!=1.0 or float(item[5])!=1.0:
                no_sim={}
                no_sim["id"]=item[0]
                no_sim["address1"]=item[1]
                no_sim["name1"]=item[2]
                no_sim["address2"]=item[3]
                no_sim["name2"]=item[4]
                no_sim["sim"]=item[5]
                
                self.not_sim.append(no_sim)
        if len(self.not_sim)==0: #相似
            self.is_notSim=False
        else: ##不相似
            self.is_notSim=True


if __name__=="__main__":
    clean()
    get_one()