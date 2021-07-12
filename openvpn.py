from OpenSSL import crypto
from time import time, gmtime, strftime
import sys, os
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import dh as _dh
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.serialization import ParameterFormat
from jinja2 import Template
import requests
from zipfile import ZipFile
import datetime
import yaml


with open('config.yml') as f:
    config = yaml.safe_load(f)

os.makedirs(config['PKI_ROOT_PATH'], mode=0o700, exist_ok=True)
TELEGRAM_BOT_BASE_URL = 'https://api.telegram.org/bot{}'.format(config['TELEGRAM_BOT_TOKEN'])

COMMANDS = [ 'createca', 'adduser', 'extenduser', 'createservercert' ]


def importCert(CERT_PATH):
	CERT = ''
	with open(CERT_PATH) as f:
		CERT = f.read()
	
	CERT = crypto.load_certificate(crypto.FILETYPE_PEM, CERT)
	return CERT


def importKey(KEY_PATH):
	KEY = ''
	with open(KEY_PATH) as f:
		KEY = f.read()
	
	KEY = crypto.load_privatekey(crypto.FILETYPE_PEM, KEY)
	return KEY

def importCRL(CRL_PATH):
	CRL = ''
	with open(CRL_PATH) as f:
		CRL = f.read()

	CRL = crypto.load_crl(crypto.FILETYPE_PEM, CRL)
	return CRL

def createCA(CN):
	CA_CERT_PATH = '%s/%s/%s.crt' %(config['PKI_ROOT_PATH'], CN, CN)
	CA_KEY_PATH = '%s/%s/%s.key' % (config['PKI_ROOT_PATH'], CN, CN)
	CRL_PATH = '%s/%s/%s.crl' % (config['PKI_ROOT_PATH'], CN, CN)

	if(os.path.exists(CA_CERT_PATH)):
		option = input('\nCA exist!! Replace? [Y/n]: ')
		if(option != 'Y'):
			print('\nExiting...\n')
			exit()

	k = crypto.PKey()
	serialnumber=int(time())

	k.generate_key(crypto.TYPE_RSA, 2048)
	
	# create a self-signed cert
	cert = crypto.X509()
	cert.get_subject().C = 'ID'
	cert.get_subject().ST = 'Jawa Barat'
	cert.get_subject().L = 'Bekasi'
	cert.get_subject().O = 'PT. Meraih Sukses Bersama Abadi'
	cert.get_subject().OU = 'VPN CA'
	cert.get_subject().CN = CN
	cert.set_serial_number(serialnumber)
	cert.gmtime_adj_notBefore(0)
	cert.gmtime_adj_notAfter(3600 * 24 * 365 * 10)
	cert.set_issuer(cert.get_subject())
	cert.set_pubkey(k)
	cert.sign(k, 'sha512')

	extensions = []
	extensions.append(crypto.X509Extension(b'basicConstraints', False, b'CA:TRUE'))
	extensions.append(crypto.X509Extension(b'keyUsage', False, b'keyCertSign, cRLSign'))

	cert.add_extensions(extensions)

	certDump = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
	keyDump = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)

	# Create CRL
	crlDump = createCRL(cert, k)

	
	os.makedirs('%s/%s/clients' % (config['PKI_ROOT_PATH'], CN), mode=0o700, exist_ok=True)
	open(CA_CERT_PATH,"wt").write(certDump.decode("utf-8"))
	open(CA_KEY_PATH, "wt").write(keyDump.decode("utf-8"))
	open(CRL_PATH, "wt").write(crlDump.decode("utf-8"))


# Create CRL. CERT(X509 object), KEY(PKey object)
def createCRL(CA_CERT, CA_KEY):
	CA_CN = CA_CERT.get_issuer().CN
	CRL_PATH = '%s/%s/%s.crl' % (config['PKI_ROOT_PATH'], CA_CN, CA_CN)
	
	crl = crypto.CRL()
	# YYYYMMDDhhmmssZ
	crl.set_lastUpdate(strftime('%Y%m%d%H%M%SZ' , gmtime()).encode())
	crl.sign(CA_CERT, CA_KEY, b'sha512')
	crlDump = crypto.dump_crl(crypto.FILETYPE_PEM, crl)

	return crlDump

def revokeCert(CA_CERT, CA_KEY, CNToRevoke):
	CA_CN = CA_CERT.get_subject().CN
	workingDir =  '%s/%s' % (config['PKI_ROOT_PATH'], CA_CN)
	CRL_PATH = '%s/%s.crl' % (workingDir, CA_CN)
	
	certToRevoke = importCert('%s/clients/%s.crt' % (workingDir, CNToRevoke))
	serial = (str(hex(certToRevoke.get_serial_number())).split('x')[1].encode())
	
	revokedCert = crypto.Revoked()
	revokedCert.set_rev_date(strftime('%Y%m%d%H%M%SZ' , gmtime()).encode())
	revokedCert.set_serial(serial)
	CRL = importCRL('%s' % (CRL_PATH))
	
	CRL.add_revoked(revokedCert)
	CRL.set_lastUpdate(revokedCert.get_rev_date())
	CRL.sign(CA_CERT, CA_KEY, b'sha512')
	CRL = crypto.dump_crl(crypto.FILETYPE_PEM, CRL)

	open(CRL_PATH, "wt").write(CRL.decode("utf-8"))
	print('\nCerificate %s revoked!\n' % (CNToRevoke))


def create_dh(key_size):
	dh_parameters = _dh.generate_parameters(generator=2, key_size=key_size, backend=backend)
	return dh_parameters.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)

def createCert(CA_CERT, CA_KEY, CN, cert_type, daysToExpire=None):
	CA_CN = CA_CERT.get_subject().CN

	if(cert_type == 'server'):
		CERT_PATH = '%s/%s/%s.crt' % (config['PKI_ROOT_PATH'], CA_CN, CN)
		KEY_PATH = '%s/%s/%s.key' % (config['PKI_ROOT_PATH'], CA_CN, CN)

	elif(cert_type == 'client'):
		CERT_PATH = '%s/%s/clients/%s.crt' % (config['PKI_ROOT_PATH'], CA_CN, CN)
		KEY_PATH = '%s/%s/clients/%s.key' % (config['PKI_ROOT_PATH'], CA_CN, CN)

	else:
		print('Invalid cert type\n')
		exit()


	if(os.path.exists(CERT_PATH)):
		option = input('\nCertificate exists, revoke old cerificate? [Y/n]: ')
		if(option != 'Y'):
			print('\nExiting...\n')
			exit()
		else:
			revokeCert(CA_CERT, CA_KEY, CN)
	
	k = crypto.PKey()
	serialnumber=int(time())
	k.generate_key(crypto.TYPE_RSA, 2048)

	# Create CSR
	csr = crypto.X509Req()
	csr.get_subject().CN = CN
	csr.set_pubkey(k)
	csr.sign(k, 'sha512')

	# Create and sign cert
	cert = crypto.X509()
	cert.set_subject(csr.get_subject())
	cert.set_pubkey(csr.get_pubkey())
	cert.set_issuer(CA_CERT.get_issuer())
	cert.set_serial_number(serialnumber)
	cert.gmtime_adj_notBefore(0)
	# Set cert expiry
	if(cert_type == 'server'):
		cert.gmtime_adj_notAfter(3600 * 24 * 365 * 10)
	elif(cert_type == 'client'):
		cert.gmtime_adj_notAfter(3600 * 24 * daysToExpire)
	else:
		print('Invalid cert type\n')
		exit()

	extensions = []
	extensions.append(crypto.X509Extension(b'basicConstraints', False, b'CA:FALSE'))

	if(cert_type == 'server'):	
		extensions.append(crypto.X509Extension(b'extendedKeyUsage', False, b'serverAuth'))
		extensions.append(crypto.X509Extension(b'keyUsage', False, b'digitalSignature, keyEncipherment'))
	else:
		extensions.append(crypto.X509Extension(b'extendedKeyUsage', False, b'clientAuth'))
		extensions.append(crypto.X509Extension(b'keyUsage', False, b'digitalSignature'))

	cert.add_extensions(extensions)
	cert.sign(CA_KEY, 'sha512')

	certDump = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8')
	keyDump = crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode('utf-8')

	open(CERT_PATH,"wt").write(certDump)
	open(KEY_PATH, "wt").write(keyDump)

	expire_date = cert.get_notAfter().decode('utf-8')
	formatted_expire_date = '{}-{}-{} {}:{} UTC'.format(expire_date[:4], expire_date[4:6], expire_date[6:8], expire_date[8:10], expire_date[10:12])

	result = {
		'certificate': certDump,
		'key': keyDump,
		'expire_date': formatted_expire_date,
		"cn": CN,
		"ca": CA_CN
	}

	return result

def createServerCert(CA_CN, SERVER_CN):
	CA_CERT = importCert('%s/%s/%s.crt' % (config['PKI_ROOT_PATH'], CA_CN, CA_CN))
	CA_KEY = importKey('%s/%s/%s.key' % (config['PKI_ROOT_PATH'], CA_CN, CA_CN))

	createCert(CA_CERT, CA_KEY, SERVER_CN, 'server')

	# create dh params
	with open('{}/{}/dh2048.pem'.format(config['PKI_ROOT_PATH'], CA_CN), 'wb') as output:
		output.write(create_dh(2048))
	
	# create server config file
	with open('server.conf.j2') as f:
		template = Template(f.read())

		with open('/etc/openvpn/server.conf', 'w') as server_conf:
			server_conf.write(
				template.render(
					ca_path = '{}/{}/{}.crt'.format(config['PKI_ROOT_PATH'], CA_CN, CA_CN),
					server_certificate_path = '{}/{}/{}.crt'.format(config['PKI_ROOT_PATH'], CA_CN, SERVER_CN),
					server_key_path = '{}/{}/{}.key'.format(config['PKI_ROOT_PATH'], CA_CN, SERVER_CN),
					crl_path = '{}/{}/{}.crl'.format(config['PKI_ROOT_PATH'], CA_CN, CA_CN),
					dh_path = '{}/{}/dh2048.pem'.format(config['PKI_ROOT_PATH'], CA_CN)
				)
			)



def addUser(CA_CN, username, daysToExpire):
	ca_root_path = '{}/{}'.format(config['PKI_ROOT_PATH'], CA_CN)

	CA_CERT = importCert('%s/%s.crt' % (ca_root_path, CA_CN))
	CA_KEY = importKey('%s/%s.key' % (ca_root_path, CA_CN))

	result = createCert(CA_CERT, CA_KEY, username, 'client', int(daysToExpire))
	
	base_client_config_path = '{}/clients/{}'.format(ca_root_path, username)
	zip_path = base_client_config_path + '.zip'
	
	with open('client.ovpn.j2') as f:
		template = Template(f.read())

		client_config_path = base_client_config_path + '.ovpn'
		with open(client_config_path, 'w') as server_conf:
			server_conf.write(
				template.render(
					server_host = config['SERVER_HOST'],
					server_port = config['SERVER_PORT'],
					ca_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, CA_CERT).decode('utf-8'),
					client_cert = result['certificate'],
					client_key = result['key']
				)
			)

		with ZipFile(zip_path, 'a') as config_zip:
			config_zip.write(client_config_path, os.path.basename(client_config_path))

		# linux config
		client_config_path = base_client_config_path + '-linux.ovpn'
		with open(client_config_path, 'w') as server_conf:
			server_conf.write(
				template.render(
					server_host = config['SERVER_HOST'],
					server_port = config['SERVER_PORT'],
					ca_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, CA_CERT).decode('utf-8'),
					client_cert = result['certificate'],
					client_key = result['key'],
					linux_client = True
				)
			)

		with ZipFile(zip_path, 'a') as config_zip:
			config_zip.write(client_config_path, os.path.basename(client_config_path))

		send_client_config(zip_path, config['TELEGRAM_CHAT_ID'], result)
		

def send_client_config(client_config_path, chat_id, details):
	api_path = '/sendDocument'
	api_url = TELEGRAM_BOT_BASE_URL + api_path


	with open('caption.txt.j2') as f:
	    template = Template(f.read())
	    caption = template.render(
		    cn = details['cn'],
		    expire_date = details['expire_date'],
		    ca = details['ca']
		    )
	# send config to telegram

	r = requests.post(
		api_url,
		data=
			{
				'chat_id': chat_id,
				'caption': caption,
				'parse_mode': 'markdown'
			},
		files={'document': open(client_config_path, 'rb')
		}
	)

def extendUser(username, daysToExpire):
	print(username)
	print(daysToExpire)	


def printHelp(case=None):
	if case == None:
		print('\nUsage: openvpn [command] [options]\n')
		print('Available commands:')
		for command in COMMANDS:
			print('- %s' % (command))
	elif(case == 'createca'):
		print('\nUsage: OpenvpnCreateCA [CN]\n')

	elif(case == 'adduser'):
		print('\nUsage: openvpn adduser [CA_CN] [username] [daysToExpire]\n')

	elif(case == 'extenduser'):
		print('\nUsage: openvpn extenduser [CA_CN] [CLIENT_CN / username] [daysToExpire]\n')

	elif(case) == 'createservercert':
		print('\nUsage: openvpn createservercert [CA_CN] [SERVER_CN]\n')


if __name__ == '__main__':
	argsLength = len(sys.argv)
	if ( argsLength == 1):
		printHelp()

	elif sys.argv[1] not in COMMANDS:
			printHelp()

	else:
		command = sys.argv[1]

		if command == 'createca':
			try:
				createCA(*sys.argv[2:])
			except TypeError:
				printHelp('createca')

		
		elif command == 'adduser':
			try:
				int(sys.argv[4])
				addUser(*sys.argv[2:])
			except (TypeError, ValueError, IndexError):
				printHelp('adduser')

		elif command == 'extenduser':
			try:
				int(sys.argv[3])
				extendUser(*sys.argv[2:])
			except (TypeError, ValueError):
				printHelp('extenduser')

		elif command == 'createservercert':
			try:
				createServerCert(*sys.argv[2:])
			except (TypeError):
				printHelp('createservercert')
			except FileNotFoundError:
				print('\nCA not found in %s/%s/%s.crt\n' % (config['PKI_ROOT_PATH'], sys.argv[2], sys.argv[2]))

		else:
			printHelp()

	
