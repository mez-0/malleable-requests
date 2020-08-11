#!/usr/bin/python3
import re, argparse

parser = argparse.ArgumentParser(description="Parse HTTP Request for Cobalt Strike Profile")
parser.add_argument("--get", metavar="", help="File containing a GET")
parser.add_argument("--post", metavar="", help="File containing a POST")
args = parser.parse_args()

if args.get == None and args.post == None:
	parser.print_help()
	quit()

class Request: # purely a data structure
	def __init__(self,verb,path,http_version,headers,cookies,user_agent):
		self.verb = verb
		self.path = path
		self.http_version = http_version
		self.headers = headers
		self.cookies = cookies
		self.user_agent = user_agent


url_regex = re.compile(r'(^GET|POST)\s(.*)\s(HTTP.*$)') # pull out the verb
header_regex = re.compile(r'(^[\w+\-?]*\w+?\:)\s(.*)') # parse the request and seperate via ':'.

def read_request_file(request_file):
	# return the contents of the file
	try:
		with open(request_file,'r') as f:
			return f.read()
	except Exception as e:
		print(e.message)
		quit()

def generate_request_dictionary(request):
	request_obj = Request(None,None,None,None,None,None)
	headers = {}
	cookies = {}
	fields = request.split('\n')
	for field in fields: # on a new line seperated entry, loop.
		if field.startswith('GET') or field.startswith('POST'):
			match = url_regex.search(field)
			if match != None:
				request_obj.verb = match.group(1)
				request_obj.path = match.group(2)
				request_obj.http_version = match.group(3)
		elif field.startswith('Cookie'):
			field = field.split('Cookie: ')[1]
			cookie_fields = field.split(';')
			for cookie in cookie_fields:
				if len(cookie) != 0:
					cookie_name = cookie.split('=')[0]
					cookie_value = cookie.split('=')[1]
					cookies[cookie_name]=cookie_value
		elif field.startswith('User-Agent'):
			request_obj.user_agent = field.split(': ')[1]
		else:
			match = header_regex.search(field)
			if match != None:
				header = match.group(1).strip(':')
				value = match.group(2)
				headers[header] = value
	request_obj.headers = headers
	request_obj.cookies = cookies
	return request_obj

def create_profile(request_obj):
	profile = ''
	profile += 'http-%s{\n' % request_obj.verb.lower()
	profile += '\tset uri "%s";\n' % request_obj.path
	profile += '\tclient {\n'
	for header_name,header_value in request_obj.headers.items():
		profile += '\t\theader "%s" "%s";\n' % (header_name,header_value)

	# just adding this chunk to make c2lint happy, just remove it from the output.S
	if request_obj.verb == 'POST':
		profile += '''
                id {
                        uri-append;
                }
                output {
                        print;
                }'''
		profile += '\n\t}'

	if request_obj.verb == 'GET':
		profile += '''        metadata {
            netbiosu;
            parameter "tmp";
        }'''
		profile += '\n}'

	print(profile)
	print()

def main():
	if args.get:
		get_request = read_request_file(args.get)
		request_obj = generate_request_dictionary(get_request)
		create_profile(request_obj)
	if args.post:
		post_request = read_request_file(args.post)
		request_obj = generate_request_dictionary(post_request)
		create_profile(request_obj)
main()
