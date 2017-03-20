import sys
from subprocess import Popen, PIPE

arg_no = len(sys.argv)
if arg_no < 1:
  print "Input the .deb image to generate docker packaget"
  print "Usage: \n ./build_image.py flex_xx.deb"
  sys.exit()

image_name = sys.argv[1]
cmd_cp = "cp " + image_name + " dockerGen/flex.deb"
ex_p = Popen(cmd_cp , shell=True, stdout=PIPE, stderr=PIPE)
out_cp, err_cp = ex_p.communicate()
print "Commmand return code " , ex_p.returncode
print out_cp.rstrip(), err_cp.rstrip()

cmd = "docker build -t \"snapos/flex:flex2\" dockerGen/"
p = Popen(cmd , shell=True, stdout=PIPE, stderr=PIPE)
out, err = p.communicate()
print "Return code: ", p.returncode
print out.rstrip(), err.rstrip()

cmd = "rm dockerGen/flex.deb"
p = Popen(cmd , shell=True, stdout=PIPE, stderr=PIPE)
out, err = p.communicate()
print "Cleanup done ", p.returncode
print out.rstrip(), err.rstrip()
