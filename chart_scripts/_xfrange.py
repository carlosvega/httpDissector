from __future__ import division
from math import log

def xfrange(start, stop, step):
	
	old_start = start #backup this value

	digits = int(round(log(10000, 10)))+1 #get number of digits
	magnitude = 10**digits
	stop = int(magnitude * stop) #convert from 
	step = int(magnitude * step) #0.1 to 10 (e.g.)

	if start == 0:
		start = 10**(digits-1)
	else:
		start = 10**(digits)*start

	data = []	#create array

	#calc number of iterations
	end_loop = int((stop-start)//step)
	if old_start == 0:
		end_loop += 1

	acc = start

	for i in xrange(0, end_loop):
		data.append(acc/magnitude)
		acc += step

	return data

print xfrange(1, 2.1, 0.1)
print xfrange(0, 1.1, 0.1)
print xfrange(-1, 0.1, 0.1)