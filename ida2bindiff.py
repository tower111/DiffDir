import logging
# from commands import getstatusoutput
from genericpath import isfile
from os import remove
from os.path import join as path_join, dirname, realpath, basename
import os
from shutil import copyfile
from config import ida_path
import config
import shutil
#coding=utf-8

# from config import log_file_name
import argparse
def is_elf(file_path):#G:\\bindiff_project\\firm\\_R6700-V1.0.2.16_10.0.57\\squashfs-root\\data
    try:
        with open(file_path,"rb")as fd:
            content=fd.read(4)[1:]
    except:
        content=""
    return content==b"ELF" and ("httpd" in file_path or "cgi" in file_path)
def GetElfs(path):
    elf_file_list=set()
    for fpathe,dirs,fs in os.walk(path):
        for f in fs:
            if is_elf(os.path.join(fpathe, f)):
                elf_file_list.add(os.path.join(fpathe, f))
                yield os.path.join(fpathe, f)
    # return elf_file_list



def ida_extract(path, args):
    """
         returns work_path where the results were stored
    """

    result=path_join(args["out_dir"],basename(path))
    try:
        os.mkdir(result)
        copyfile(path,path_join(result,basename(path)))
    except:
        pass
    # print("bindiff")
    export_script_path = path_join(config.projPath, "idaextractor", 'export.py')
    cmd="{} -B -A -S{} {}".format(args['idal64_path'],export_script_path,
                                                          path_join(result,basename(path))+"")
    r1=os.system(cmd+" > /dev/null")

    if  r1!=0:#
        logging.warning("IDA command {} had errors. Giving it another (last) chance.".format(extract_command))

        r1 = os.system(cmd)
        if r1 !=0:
            raise Exception("bindiff export error{}   {}".format(cmd, r1))
    # work_path = dirname(path)
    return path,result
def init(input,output):
    # ida_path=os.path.join(ida_path,"ida64.exe")
    # ida_path="C/Program Files/IDA 7.0/ida64.exe"
    # os.system(ida_path)
    parser = argparse.ArgumentParser(description='Index executables.')
    parser.add_argument('--idal64-path', default=ida_path, type=str,
                                          help="Path to the idal64 executable (default={}, make sure it has jsonpickle!)".
                                          format(ida_path))
    #"C:\\Users\\tower\\Desktop\\Nero-ida\\TRAIN"
    parser.add_argument('--input_dir', type=str,default=input,
                        help="need input dir --input {}".format(input))
    parser.add_argument('--out_dir', type=str,default=output,
                    help="need output dir --output {}".format(output))
    args = vars(parser.parse_args())


    # os.system("cp -r {} {}".format("/home/tower/Desktop/work/tower/my_test","/home/tower/Desktop/work/tower/Nero"))
    return args

class UnsupportedExeForIda(Exception):
    # right now thrown when CPP exe is encountered
    pass

def main(input,output):
    args=init(input,output)
    
    try:
        os.mkdir(output)
    except:
        pass
    row2binexport={}
    for elf_path in GetElfs(args["input_dir"]):
        raw,binexport=ida_extract(elf_path,args)
        # row2binexport[raw]=binexport
        yield (raw,binexport)
# if __name__=="__main__":
#     main()
