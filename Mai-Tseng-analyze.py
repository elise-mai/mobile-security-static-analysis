from androguard.core.bytecodes import apk, dvm
from androguard.core.analysis.analysis import Analysis
from zipfile import BadZipFile

import sys
import os

def analyze_permissions():
	i = 0
	exact = 0
	over = 0
	atleast_25 = 0
	atleast_50 = 0
	atleast_75 = 0
	
	for file in os.listdir(os.getcwd()):
		if file.startswith('.') == True or file.endswith('.apk') == False:
			continue
		else:
			permission_list = []
			permission_tracker = []
			try:
				i += 1
				a = apk.APK(file)
				manifest = str(a.get_android_manifest_axml().get_xml()).split(' ')
				
				j = -1
				for ele in manifest:
					j += 1
					if 'uses-permission' in ele:
						permission = manifest[j+1].translate({ord(char): None for char in '"/>'}).replace('\\n','').replace("android:name=",'')
						permission_list.append(permission)

				'''
				# print the permissions requested 
				for permission in permission_list:
					print(permission)
				'''

				d = dvm.DalvikVMFormat(a.get_dex())
				s = d.get_strings()
				
				for item in s:
					if item in permission_list and item not in permission_tracker:
						permission_tracker.append(item)
						#print(item)

				if len(permission_list) == len(permission_tracker):
					exact += 1
				elif len(permission_list) > len(permission_tracker):
					over += 1

				try:
					if len(permission_tracker)/len(permission_list) >= 0.75:
						atleast_75 += 1
					if len(permission_tracker)/len(permission_list) >= 0.5:
						atleast_50 += 1
					if len(permission_tracker)/len(permission_list) >= 0.25:
						atleast_25 += 1
				except ZeroDivisionError:
					pass		

				#print("App #" + str(i) + ". Permissions requested: " + str(len(permission_list)) + " vs. permissions used: " + str(len(permission_tracker)))

				'''
				# control for testing a single apk file
				if i==1:
					break
				'''
			except BadZipFile:
				print(file + ': BadZipFile Error')
				continue
	print("PERMISSION ANALYSIS RESULT:")
	print("Out of %s apps, %s used the exact number of permissions that they requested." % (i, exact))
	print("%s requested more permissions than they used." % over)
	print("%s apps used at least three-fourths of the permissions they requested, %s used at least half, and %s used at least a quarter." % (atleast_75, atleast_50, atleast_25))

def analyze_components():
	i = 0
	count = 0
	internet = 0
	phone_state = 0
	api = 0
	sms = 0
	storage = 0
	for file in os.listdir(os.getcwd()):
		if file.startswith('.') == True or file.endswith('.apk') == False:
			continue
		else:
			exported = []
			try:
				i += 1
				a = apk.APK(file)
				manifest = str(a.get_android_manifest_axml().get_xml()).split(' ')
				#print("Checking app #%s" % i)
				
				j = -1
				for ele in manifest:
					j += 1
					if 'exported="true"' in ele:
						component = manifest[j-1]
						if 'android:name' not in component:
							'''
							idx = j
							while 'android:name' not in component:
								idx -= 1
								component = manifest[idx]
							#print("Component " + component + " is exported, but also permission-protected.")
							if component not in exported:
								exported.append(component)
							'''
							pass
						else:
							#print("Component " + component + " is exported.")
							if component not in exported:
								exported.append(component.translate({ord(char): None for char in '"/>\\'}).replace('\\n','').replace("android:name=",''))
					elif '<intent-filter>' in ele:
						component = str()
						if 'android:name' not in component:
							idx = j
							while 'android:name' not in component:
								idx -= 1
								component = manifest[idx]
								if 'exported="false"' in component or 'android:permission' in component:
									break
							if 'android:name' in component and component not in exported:
								#print("Component " + component + " has intent filters.")
								exported.append(component.translate({ord(char): None for char in '"/>\\'}).replace('\\n','').replace("android:name=",''))
			
				activities_list = []
				for act in a.get_activities():
					activities_list.append(act)
				
				# remove exported Activities from the list because they are not as prone to intent hijacking as background components
				# focus on Services, Receivers, and Providers
				for e in exported:
					if e in activities_list:
						exported.remove(e)

				if len(exported) >= 1:
					#print("App #%d has %d" % (i, len(exported)) + " unprotected exported components.")
					'''
					#printing the exported components
					for e in exported:
						print(e)
					'''
					count += 1

					# pontential capability leaks
					permissions = a.get_permissions()
					has_internet_perm = False
					has_phone_state_perm = False
					has_sensitive_api_perm = False
					has_sms_perm = False
					has_storage_perm = False
				
					for perm in permissions:
						if 'INTERNET' in perm or 'ACCESS_NETWORK_STATE' in perm or 'ACCESS_WIFI_STATE' in perm:
							has_internet_perm = True
						elif 'READ_PHONE_STATE' in perm:
							has_phone_state_perm = True
						elif 'ACCESS_FINE_LOCATION' in perm or 'CAMERA' in perm or 'RECORD_AUDIO' in perm:
							has_sensitive_api_perm = True
						elif 'SEND_SMS' in perm or 'WRITE_SMS' in perm or 'READ_SMS' in perm or 'RECEIVE_SMS' in perm:
							has_sms_perm = True
						elif 'READ_EXTERNAL_STORAGE' in perm or 'WRITE_EXTERNAL_STORAGE' in perm:
							has_storage_perm = True
					if has_internet_perm:
						internet += 1
					if has_phone_state_perm:
						phone_state += 1
					if has_sensitive_api_perm:
						api += 1
					if has_sms_perm:
						sms += 1
					if has_storage_perm:
						storage += 1
			except BadZipFile:
				print(file + ': BadZipFile Error')
				continue
	print("COMPONENT ANALYSIS RESULT:")			
	print("Total number of apps with unprotected exported components (specifically, Services, Receivers, and Providers): %s" % count)
	print("Potential for capability leaks from intent hijacking:")
	print("-- Number of vulnerable apps with INTERNET permissions: %s" % internet)
	print("-- Number of vulnerable apps with READ_PHONE_STATE permissions: %s" % phone_state)
	print("-- Number of vulnerable apps with sensitive API permissions (location, camera, or microphone access): %s" % api)
	print("-- Number of vulnerable apps with SMS permissions: %s" % sms)
	print("-- Number of vulnerable apps with EXTERNAL_STORAGE permissions: %s" % storage)

def analyze_webviews():
	i = 0
	j = 0
	k = 0
	l = 0

	for file in os.listdir(os.getcwd()):
		if file.startswith('.') == True or file.endswith('.apk') == False:
			continue
		else:
			try:
				i += 1
				a = apk.APK(file)
				sdk = a.get_target_sdk_version()
				#print(str(i) + '. ' + file + ' Target SDK: ' + str(sdk))

				d = dvm.DalvikVMFormat(a.get_dex())
				s = d.get_strings()
				has_webview = False
				has_jsinterface= False
				has_jsenabled = False
	
				for item in s:
					if 'Landroid/webkit/WebView;' in item:
						has_webview = True
					if 'JavascriptInterface' in item:
						has_jsinterface = True
					if 'JavaScriptEnabled' in item:
						has_jsenabled = True
					if has_webview and has_jsinterface and has_jsenabled:
						try:
							if int(sdk) <= 16:
								j += 1
								#print('App #%s is always vulnerable.' % i)
							else:
								k += 1
								#print('App #%s is vulnerable on outdated devices.' % i)
						except:
							l += 1
							#print('App #%s has no target SDK level. Potential vulnerability.' % i)
						break

				'''
				# control for testing a single apk file
				if i==1:
					break
				'''
			except BadZipFile:
				print(file + ': BadZipFile Error')
				continue
	print("WEBVIEW ANALYSIS RESULT:")
	print("Total number of apps that are always vulnerable: " + str(j))
	print("Total number of apps that are vulnerable on outdated devices: " + str(k))
	print("Total number of apps with potential vulnerability but no target SDK level: " + str(l))

bad_cert_validation_keywords = ['AcceptAllTrustManager', 'AcceptAllSSLSocketFactory',
'AllTrustManager', 'AllTrustingSSLSocketFactory',
'DummyTrustManager', 'AllTrustSSLSocketFactory',
'EasyX509TrustManager', 'AllSSLSocketFactory',
'FakeTrustManager', 'DummySSLSocketFactory',
'FakeX509TrustManager', 'EasySSLSocketFactory',
'FullX509TrustManager', 'FakeSSLSocketFactory',
'NaiveTrustManager', 'InsecureSSLSocketFactory',
'NonValidatingTrustManager', 'NonValidatingSSLSocketFactory',
'NullTrustManager', 'NaiveSslSocketFactory',
'OpenTrustManager', 'SimpleSSLSocketFactory',
'PermissiveX509TrustManager', 'SSLSocketFactoryUntrustedCert',
'SimpleTrustManager', 'SSLUntrustedSocketFactory',
'SimpleX509TrustManager', 'TrustAllSSLSocketFactory',
'TrivialTrustManager', 'TrustEveryoneSocketFactory',
'TrustAllManager', 'NaiveTrustManagerFactory',
'TrustAllTrustManager', 'LazySSLSocketFactory',
'TrustAnyCertTrustManager', 'UnsecureTrustManagerFactory',
'UnsafeX509TrustManager', 'VoidTrustManager', 'SslErrorHandler;->proceed()']

bad_hostname_validation_keywords = ['AllowAllHostnameVerifier',
'FakeHostnameVerifier', 'NaiveHostnameVerifier', 'AcceptAllHostnameVerifier',
'ALLOW_ALL_HOSTNAME_VERIFIER'] 

def analyze_ssl():
	i = 0
	j = 0 # keeps track of implementations of known broken TrustManager/SSLSocketFactory classes
	k = 0 # keeps track of improper hostname validation
	l = 0 # keeps track of custom TrustManagers that do not perform any certificate checks
	m = 0 # keeps track of custom HostnameVerifiers that do not perform any hostname checks
	for file in os.listdir(os.getcwd()):
		if file.startswith('.') == True or file.endswith('.apk') == False:
			continue
		else:
			has_bad_cert_validation = False
			has_bad_hostname_validation = False
			method_returns_void = False
			method_returns_true = False
			try:
				i += 1
				a = apk.APK(file)
				sdk = a.get_target_sdk_version()
				#print(str(i) + '. ' + file + ' Target SDK: ' + str(sdk))

				d = dvm.DalvikVMFormat(a.get_dex())
				s = d.get_strings()
				#print("Currently checking app #%s" % i)
				for item in s:
					for keyword in bad_cert_validation_keywords:
						if keyword in item:
							has_bad_cert_validation = True
					for keyword in bad_hostname_validation_keywords:
						if keyword in item:
							has_bad_hostname_validation = True
				
				if has_bad_cert_validation:
					j += 1
				else:
					ins_list = []
					for current_class in d.get_classes():
						for method in current_class.get_methods():
							if 'checkClientTrusted' in method.get_name():
								#print("[*] ",method.get_name(), method.get_descriptor())
								#print(str(current_class) + " implements custom certificate validation. Manual analysis required.")
								byte_code = method.get_code()
								if byte_code != None:
									byte_code = byte_code.get_bc()
									for ins in byte_code.get_instructions():
										ins_list.append(ins.get_name())
							if len(ins_list) == 1:
								method_returns_void = True
					if method_returns_void:
						l += 1
				if has_bad_hostname_validation:
					k += 1
				else:
					ins_list = []
					for current_class in d.get_classes():
						for method in current_class.get_methods():
							if 'verify' in method.get_name() and 'Ljava/lang/String; Ljavax/net/ssl/SSLSession;' in method.get_descriptor():
								#print("[*] ",method.get_name(), method.get_descriptor())
								#print(str(current_class) + " implements custom hostname validation. Manual analysis required.")
								byte_code = method.get_code()
								if byte_code != None:
									byte_code = byte_code.get_bc()
									for ins in byte_code.get_instructions():
										#print(ins.get_name(),ins.get_output())
										ins_list.append(ins.get_name())
							if len(ins_list) == 2:
								method_returns_true = True
					if method_returns_true:
						m += 1
			except BadZipFile:
				print(file + ': BadZipFile Error')
				continue

	print("SSL ANALYSIS RESULT:")
	print("Apps that implement broken TrustManager/SSLSocketFactory classes: %s" % j)
	print("Apps that implement improper custom TrustManagers: %s" % l)
	print("Total number of apps that implement improper certificate verification: %s" % str(j+l))
	print("Apps that implement broken HostnameVerifier classes: %s" % k)
	print("Apps that implement improper custom HostnameVerifiers: %s" % m)
	print("Total number of apps that implement improper hostname verification: %s" % str(k+m))

def main():
	analyze_permissions()
	analyze_components()
	analyze_webviews()
	analyze_ssl()
	
if __name__ == "__main__":
	main()