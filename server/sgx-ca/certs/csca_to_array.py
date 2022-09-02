#!/usr/bin/python2
cert_name = "csca-germany-101-self-signed.cer" # fa
#cert_name = "csca-germany_103_self_signed.cer" # gunnar

with open("array_def.c", "w") as out:
	out.write("static const unsigned char csca_raw[] = {\n")
	with open(cert_name) as fd:
		i = 0
		while 1:
			byte_s = fd.read(1)
			if not byte_s:
				break
			out.write("0x{:02x},".format(ord(byte_s)))
			i += 1
			if i > 10:
				i = 0
				out.write('\n')
	out.write("\n};")
