#!/bin/python3

import datetime
import cryptography
from Crypto import Random

from Crypto.Cipher import AES as AES
from Crypto.Cipher import DES as DES
from Crypto.Cipher import DES3 as DES3
from Crypto.PublicKey import RSA as RSA
from Crypto.Cipher import Blowfish as Blowfish
# from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as X25519

import matplotlib.pyplot as plt


def main():
	resultats = []
	resultats.extend(tester(32))
	resultats.extend(tester(64))
	resultats.extend(tester(128))
	resultats.extend(tester(256))
	resultats.extend(tester(512))
	resultats.extend(tester(1024))
	resultats.extend(tester(2048))
	resultats.extend(tester(4096))
	resultats.extend(tester(8192))
	resultats.extend(tester(16384))
	# print(resultats)
	faire_graphe(resultats)

#genere le graphique
def faire_graphe(resultats):
	rsa = []
	# x25519 = []
	aes = []
	blow = []
	des = []
	des3 = []
	for res in resultats:
		(label,value) = res
		if(label=='RSA'):
			if(value):
				rsa.append(value)
			else:
				rsa.append(0)
		# if(label=='X25519'):
		# 	x25519.append(value)
		if(label=='AES'):
			aes.append(value)
		if(label=='DES'):
			des.append(value)
		if(label=='triple DES'):
			des3.append(value)
		if(label=='Blowfish'):
			blow.append(value)
	axe = [32,64,128,256,512,1024,2048,4096,8192,16384]
	# plt.plot(axe,aes,'bs',axe,des3,'gs',axe,des,'g--',axe,blow,'b--',axe[:3],rsa[:3],'r^',axe,x25519,'r--')

	# la ligne suivante genere le graphique :
	# AES en carres bleus
	# DES en pointiles verts
	# 3DES en carres verts
	# Blowfish en pointilles bleus
	plt.plot(axe,aes,'bs',axe,des3,'gs',axe,des,'g--',axe,blow,'b--',axe[:3],rsa[:3],'r^')
	plt.title('Vitesse des algorithmes en fonction de la taille du message à chiffrer')
	plt.show()


def tester(msgSize):
	resultats = []
	input_msg = Random.new().read(msgSize)
	# print(input_msg)

	#preparer AES
	aes_IV = Random.new().read(AES.block_size )
	aes_symKey = Random.new().read(AES.block_size )
	cipher_aes = AES.new(aes_symKey,AES.MODE_CBC,aes_IV)
	#preparer RSA
	rsa_privKey = RSA.generate(1024, Random.new().read) #generate pub and priv key
	rsa_publicKey = rsa_privKey.publickey() # pub key export for exchange
	#preparer DES
	des_symKey = b'8bytekey'
	des_IV = Random.new().read(DES.block_size )
	cipher_des = DES.new(des_symKey,DES.MODE_OFB,des_IV)
	#preparer 3DES
	des3_symKey = b'Sixteen byte key'
	des3_IV = Random.new().read(DES3.block_size )
	cipher_3des = DES3.new(des3_symKey,DES3.MODE_OFB,des3_IV)
	#Préparer Blowfish
	blow_symKey = b'une cle de taille arbitraire'
	blow_IV = Random.new().read(Blowfish.block_size)
	cipher_blow = Blowfish.new(blow_symKey, Blowfish.MODE_CBC,blow_IV)
	#preparer X25519
	# x25519_privKey = X25519.generate()
	# x25519_pubKey = x25519_privKey.public_key()


	resultats.append(chronometrer_rsa_1('RSA',rsa_privKey,rsa_publicKey, input_msg))
	# resultats.append(chronometrer_x25519('X25519',x25519_privKey,x25519_pubKey,input_msg))
	resultats.append(chronometrer_sym('AES', cipher_aes, input_msg))
	resultats.append(chronometrer_sym('Blowfish',cipher_blow, input_msg))
	resultats.append(chronometrer_sym('DES',cipher_des, input_msg))
	resultats.append(chronometrer_sym('triple DES',cipher_3des, input_msg))

	return resultats



### FONCTIONS POUR CHIFFRER ET CHRONOMETRER

# def chronometrer_x25519(algo,privKey,publicKey,input_msg):
# 	print(algo)
# 	chrono = None
	
# 	try:
# 		tstart = datetime.datetime.now()
# 		message = privKey.sign(input_msg)
# 		tfinish = datetime.datetime.now()
# 		chrono = (tfinish - tstart).microseconds
# 	except ValueError as e:
# 		print('### ERREUR : '+str(e)+' = (en français) : Le message à chiffrer est trop large')

	
# 	print(algo+' : fini en : '+str(chrono))
# 	return(algo, chrono)


def chronometrer_rsa_1(algo, privKey,publicKey, input_msg):
	print(algo)
	chrono = None
	
	try:
		tstart = datetime.datetime.now()
		# message = publicKey.encrypt(input_msg,32)
		message = privKey.sign(input_msg,32)
		tfinish = datetime.datetime.now()
		chrono = (tfinish - tstart).microseconds
	except ValueError as e:
		print('### ERREUR : '+str(e)+' = (en français) : Le message à chiffrer est trop large')

	
	print(algo +' : fini en : '+str(chrono))
	return(algo, chrono)


def chronometrer_sym(algo,cipher, input_msg):
	print(algo)
	tstart = datetime.datetime.now()

	message = cipher.encrypt(input_msg)
	# print(message)

	tfinish = datetime.datetime.now()
	chrono = (tfinish - tstart).microseconds
	print(algo +' : fini en : '+str(chrono))
	return(algo, chrono)


## POUR ROMAIN SEULEMENT


if __name__ == '__main__':

	main()
	
