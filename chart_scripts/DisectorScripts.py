#! /usr/bin/env python
from __future__ import division         #float division
from collections import defaultdict, OrderedDict, Counter
from math import sqrt, ceil, log
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties
import numpy as np
import argparse, sys, gc, json, fileinput, re, os, time
from multiprocessing import Pool
from itertools import repeat

urls = Counter()
domains = Counter()
ips = Counter()

codes = Counter()
code_counter = {}
response_times = Counter() 
resp_times = []
max_response_time = 0

sample_length = 0

args = None

#regex
regex_ss = None
regex_hits = None

#GetOpt
def parse_args():
	global regex
	global args
	parser = argparse.ArgumentParser(description='Creates charts with the information from the dissector..')
	# parser.add_argument('integers', metavar='N', type=int, nargs='+',
	#                    help='an integer for the accumulator')
	parser.add_argument('-o', '--output', nargs=3, dest='f_name', required=False,
	                   help='Charts filenames:\n{ccdf, stats, hits}', default=['ccdf', 'stats', 'hits'])
	parser.add_argument('-f', '--format', dest='format', default='png',
					   help='Output chart format. {png (default), svg, pdf}')
	parser.add_argument('-i', '--input', dest='input', default='-',
					   help='Input file. Default = stdin')
	parser.add_argument('-r', '--resolution', dest='dpi', default='100', type=int,
					   help='Resolution of charts in DPI. Default 100')
	parser.add_argument('-d', '--dir', dest='dir', default=None,
					   help='Directory where output will be save')
	parser.add_argument('--filter-mode', dest='f_mode', default='all',
					   help='Filter mode. {domain, url, ip}')
	parser.add_argument('--filter', dest='filter',
					   help='Filter regex')
	parser.add_argument('--top', dest='top', default = 10,
					   help='Chart bars top. Default = 10')

	args = parser.parse_args()


	if args.f_mode in ('domain','url','ip'):
		regex = re.compile(args.filter)

	if args.dir != None:
		try:
			if not os.path.exists(args.dir):
				os.makedirs(args.dir)
		except OSError as exception:
			if exception.errno != errno.EEXIST:
				raise


	return args

def autolabel(rects, ax, hor=False, lg=False):
	    # attach some text labels
	    
		if hor == True:
			for rect in rects:
				width = rect.get_width()
				height = rect.get_height()
				ax.text(width*0.5, rect.get_y()+height/2., '%d'%int(width), va='center', ha='center', alpha=0.85, size='xx-small')

		else:
			for rect in rects:
			    height = rect.get_height()
			    width = rect.get_width()
			    if lg == True:
			    	ax.text(rect.get_x()+width/2., sqrt(height), '%d'%int(height), va='center', alpha=0.85, ha='center', rotation=90, size='x-small')
			    else:
			    	ax.text(rect.get_x()+width/2., 0.5*height, '%d'%int(height), va='center', alpha=0.85, ha='center', size='xx-small')


#JSON STUFF
def JSON_CCDF(data):

	path = 'json'

	if args.dir != None:
		path = args.dir + '/json'

	try:
		if not os.path.exists(path):
			os.makedirs(path)
	except OSError as exception:
		if exception.errno != errno.EEXIST:
			raise

	with open(path+'/CCDF.json', 'w') as f:
		f.write(json.dumps(data))

def JSON_hits(data):

	path = 'json'

	if args.dir != None:
		path = args.dir + '/json'

	try:
		if not os.path.exists(path):
			os.makedirs(path)
	except OSError as exception:
		if exception.errno != errno.EEXIST:
			raise

	with open(path +'/hits.json', 'w') as f:
		f.write(json.dumps(data, sort_keys=True))

def JSON_response_codes(code_counter, codes):

	path = 'json'

	if args.dir != None:
		path = args.dir + '/json'

	try:
		if not os.path.exists(path):
			os.makedirs(path)
	except OSError as exception:
		if exception.errno != errno.EEXIST:
			raise

	data = {}
	data['codes'] = code_counter.items()
	for c in codes:
		data[c] = codes[c].items()

	with open(path + '/response_codes.json', 'w') as f:
		f.write(json.dumps(data, sort_keys=True))

def get_code_counter(code):
	if code not in code_counter:
		code_counter[code] = Counter()

	return code_counter[code] 


def get_info_from_stdin():
	global sample_length
	global max_response_time
	global response_times
	global resp_times
	global codes
	global code_counter
	global ips
	global urls
	global domains
	global args
	global regex
	for line in fileinput.input(args.input):
		line = line.split('|')
		if len(line) != 11:
			continue

		if args.f_mode == 'all':
			None
		elif args.f_mode == 'domain':
			if regex.search(line[9].split('/')[0]) == None:
				continue
		elif args.f_mode == 'url':
			if regex.search(line[9]) == None:
				continue
		elif args.f_mode == 'ip':
			if regex.search(line[2]) == None:
				continue
		else:
			print 'Invalid CCDF filter mode'
			sys.exit()
		
		sample_length += 1
		#RESPONSE CODES
		codes.update([line[8]])
		counter = get_code_counter(line[8])
		counter.update([line[2]])
		#HITS
		urls.update([line[9]])
		domains.update([line[9].split('/')[0]])
		ips.update([line[2]])
		#CCDF
		r = float(line[6])
		resp_times.append(r)
		response_times.update([int(r*1000)])
		if r > max_response_time:
			max_response_time = r


def write_CCDF_chart():
	global args
	global response_times

	path = 'stats'

	if args.dir != None:
		path = args.dir + '/stats'

	try:
		if not os.path.exists(path):
			os.makedirs(path)
	except OSError as exception:
		if exception.errno != errno.EEXIST:
			raise

	#RESPONSE TIMES
	response_times = sorted(response_times.items())
	CCDF_all_data = []
	suma = 0
	for d in response_times:
		number = d[0]
		cant = d[1]
		CCDF_all_data.append((number, cant, cant/sample_length, 1-suma))
		suma += cant/sample_length

	yaxis_data = []
	xaxis_data = []

	json_data = []
	json_data.append(['Probabilidad Acumulada', 'Tiempo de Respuesta'])

	for s in CCDF_all_data:
		yaxis_data.append(s[3])
		xaxis_data.append(s[0])
		json_data.append([s[0], s[3]])

	plt.clf()
	plt.plot(xaxis_data, yaxis_data)
	plt.yticks(np.arange(0, 1.1, 0.1))
	plt.grid()
	plt.title("CCDF")
	plt.xscale('log')
	plt.xlabel('Response Time (ms)')
	plt.savefig(path + '/' + args.f_name[0] + '.' + args.format, dpi=args.dpi)
	JSON_CCDF(json_data)

def write_hits_chart():
	
	global args
	global urls
	global ips
	global domains

	path = 'hits'

	if args.dir != None:
		path = args.dir + '/hits'

	try:
		if not os.path.exists(path):
			os.makedirs(path)
	except OSError as exception:
		if exception.errno != errno.EEXIST:
			raise

	top = args.top

	#HITS
	# urls = sorted(urls.items(), key=lambda i: i[1], reverse=True)[:top]
	# domains = sorted(domains.items(), key=lambda i: i[1], reverse=True)[:top]
	# ips = sorted(ips.items(), key=lambda i: i[1], reverse=True)[:top]

	urls = urls.most_common(top)
	domains = domains.most_common(top)
	ips = ips.most_common(top)

	hits_data = [domains, urls, ips]
	mode = len(hits_data)
	types = ('Domains','URLs','IPs')
	title = None

	json_data = {}

	for i in xrange(0, mode):
		data = hits_data[i]
		plt.clf()
		
		fig, ax = plt.subplots()
		labels = [x[0] for x in data]
		if mode == 1:
			if args.hits_f_mode == 'url':
				title='URLs'
			elif args.hits_f_mode == 'ip':
				title='IPs'
			else:
				title='Domains'
		else:
			title=types[i]
			
		if title == 'URLs':
			bars = ax.barh(range(0,top), [x[1] for x in data], label='Data', color='g', alpha=0.5)
			plt.yticks(range(top+1), labels, size='xx-small', va='bottom')
			plt.xticks(size='small')
			plt.xlabel('Hits')
			autolabel(bars, ax, hor=True)
		else:
			bars = ax.bar(range(0, top), [x[1] for x in data], label='Data', color='g', alpha=0.5)
			plt.xticks(range(top+1), labels, rotation=45, size='x-small')
			plt.yticks(size='small')
			plt.ylabel('Hits')
			autolabel(bars, ax)

		plt.title(title, size='x-large')
		
		plt.savefig(path + '/' + args.f_name[2] + '_' + title + '.' + args.format, bbox_inches='tight', dpi=args.dpi)
		
		json_data[title] = data
		
	JSON_hits(json_data)

def write_stats_chart():
	global args
	global resp_times
	global sample_length
	global max_response_time

	path = 'stats'

	if args.dir != None:
		path = args.dir + '/stats'

	try:
		if not os.path.exists(path):
			os.makedirs(path)
	except OSError as exception:
		if exception.errno != errno.EEXIST:
			raise

	suma = 0
	suma_square = 0

	for r in resp_times:
		suma += r
		suma_square += r*r

	stats_data = (sample_length, suma/sample_length, 
		sqrt(suma_square/sample_length - (suma/sample_length)**2), 
		suma_square/sample_length - (suma/sample_length)**2)

	plt.clf()
	#Data
	plt.plot(resp_times, marker='.', linestyle='None', color='g', label='Data', alpha=0.15)
	#Mean
	mean_label = 'Mean (' + str(round(stats_data[1], 3)) + ')'
	plt.axhline(y=stats_data[1], xmin=0, xmax=1, linestyle='--', linewidth=1, color='r', label=mean_label, alpha=0.75)
	#Deviation
	std_dev_label = 'Deviation (' + str(round(stats_data[2], 3)) + ')'
	plt.axhline(y=stats_data[2], xmin=0, xmax=1, linestyle='--', linewidth=1, color='b', label=std_dev_label, alpha=0.75)
	#Grid and scale
	plt.grid()
	plt.xscale('linear')
	#ticks
	max_ytick = int(10 * round(float(max_response_time)/10))
	plt.yticks(np.arange(0, max_ytick, max_ytick/10))
	#Labels and legend
	plt.title("Stats")
	plt.ylabel('Response Time (ms)')
	plt.xlabel('Nth Response Time.')
	fontP = FontProperties()
	fontP.set_size('xx-small')
	plt.legend(prop = fontP, loc = 'center', bbox_to_anchor = (1, 1.06))
	plt.savefig(path + '/' + args.f_name[1] + '.' + args.format, dpi=args.dpi)

def plot_response_code_chart(values, labels,lg=False, rotation=0, grid=True):	
		plt.clf()
		plt.close()
		fig, ax = plt.subplots()
		if lg == True:
			plt.yscale('log')
		if grid == True:
			plt.grid(alpha=0.25)
		bars = ax.bar(range(0, len(labels)), values, label='Data', color='g', alpha=0.5)
		plt.xticks(range(len(labels)+1), labels, rotation=rotation, ha='center', size='x-small')
		plt.tight_layout()
		autolabel(bars, ax, lg=lg)
		return plt

def write_response_code_loop_function(aux_args):

	path = aux_args[0]
	file_format = aux_args[1]
	dpi = aux_args[2]
	c = aux_args[3]
	code_counter_c = aux_args[4]

	code_counter_c = code_counter_c.most_common(15)
	chart = plot_response_code_chart([x[1] for x in code_counter_c], [x[0] for x in code_counter_c], rotation=45)
	chart.title('ResponseCode '+c, size='x-large')
	chart.ylabel('Responses')
	chart.savefig(path + '/responseCode_' + c + '.' + file_format, bbox_inches='tight', dpi=dpi)


def write_response_codes():
	global code_counter
	global codes
	global args

	path = 'responseCodes'

	if args.dir != None:
		path = args.dir + '/responseCodes'

	try:
		if not os.path.exists(path):
			os.makedirs(path)
	except OSError as exception:
		if exception.errno != errno.EEXIST:
			raise

	code_set = sorted(codes.keys())
	code_values = sorted(codes.values(), reverse=True)
	code_counter_data = sorted(codes.items(), key=lambda i: i[1], reverse=True)

	chart = plot_response_code_chart(code_values, code_set, lg=True, rotation=-45)
	chart.title('ResponseCodes', size='x-large')
	chart.savefig(path + '/responseCodes' + '.' + args.format, bbox_inches='tight', dpi=args.dpi)

	aux_args = []
	for c in code_counter:
		aux_args.append((path, args.format, args.dpi, c, code_counter[c]))
		
	p.map(write_response_code_loop_function, aux_args)

	JSON_response_codes(codes, code_counter)

if __name__ == '__main__':
	p = Pool(4)
	parse_args()

	start = time.time()
	get_info_from_stdin()
	end = time.time()

	print 'Fichero Leido ',
	print end-start,
	print ' segundos'

	if sample_length == 0:
		print '0 lines to parse'
		sys.exit()

	start = time.time()
	write_CCDF_chart()
	write_hits_chart()
	write_stats_chart()
	write_response_codes()
	end = time.time()
	print 'Graficas Completadas ',
	print end-start,
	print ' segundos'


