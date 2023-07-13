import os
ida_path="""/Applications/IDA_Pro_7.5/ida.app/Contents/MacOS/idat"""
projPath=os.path.dirname(os.path.realpath(__file__))
input1=projPath+"/in/13/"   #old
# os.path.join(projPath, 'R6700-V1.0.2.16_10.0.57','squashfs-root')#"G:\\bindiff_project\\firm\\R6700-V1.0.2.16_10.0.57\\squashfs-root"
output1=projPath+"/exter_result/1"#old

input2=projPath+"/in/14/" #new
# input2=os.path.join(projPath, 'R6700-V1.0.2.26_10.0.61','squashfs-root')#"G:\\bindiff_project\\firm\\R6700-V1.0.2.26_10.0.61\\squashfs-root"
output2=projPath+"/exter_result/2"   #new

tmp_dir=projPath+"/temp/"
temp=projPath+"/temp/extra.json"
bindiff_dir=projPath+"/bindiff_dir/"

dif_result=projPath+"/temp/dif_result.json"
dif_result_log=projPath+"/temp/dif_result.log"