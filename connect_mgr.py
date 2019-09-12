import telnetlib
import paramiko
import re
import time

# this library is born to manage telnet/ssh connections, with or without a proxy,
# usually toward Cisco devices. It can be potentially used also toward other
# routers or devices, probably without any problems, but has never been tested for this.


# this dictionary contains all the data related to the proxy, router's username
# and pwd, log directory and so on. In case there is no proxy, the host value
# MUST be empty and only the other values should be filled. This approach is
# useful to avoid massive changes of these parameters on many scripts in case
# these parameters change. We suppose of course that ALL routers have the same
# credentials and password prompt, otherwise this should be managed on the script's
# side using this class, and creating different profiles

proxy_data = {  'profile_with_proxy' : {  "ssh_proxy" : "",
                            "proxy_prompt" : "",
                            "proxy_usr" : "",
                            "proxy_pwd" : "",
                            "rou_user" : "",
                            "rou_pwd" : "",
                            # this is the pwd prompt to connect to the routers
                            "rou_pwd_prompt" : "",
                            "log_dir" : ""    
                        },
                # no proxy in this case
                'profile_no_proxy'  : { 
                                "rou_user" : "",
                                "rou_pwd" : "",
                                "rou_pwd_prompt" : "",
                                "log_dir" : ""    
                              }
              }

# object must be created passing the string that identifies the customer and/or the proxy
# to which we must connect before reaching all target devices.
class ssh_manager ():
    CHANNEL_LENGTH = 10000
    
    def __init__(self, proxy_id):
        self.ssh = None
        self.ssh_proxy = None
        self.config_prompt = ''
        self.router_prompt = ''
        self.router_name = ''
        self.LOG_FLAG = 0
        
        # if there is no proxy in between, let's skeep all the other data
        if proxy_id in proxy_data:
            self.rou_user = proxy_data[proxy_id]['rou_user']
            self.rou_pwd = proxy_data[proxy_id]['rou_pwd']
            self.pwd_prompt = proxy_data[proxy_id]['rou_pwd_prompt']
            self.log_dir = proxy_data[proxy_id]['log_dir']
            if 'ssh_proxy' in proxy_data[proxy_id]:
                self.ssh_proxy = proxy_data[proxy_id]['ssh_proxy']
                self.prompt = proxy_data[proxy_id]['proxy_prompt']
                self.proxy_prompt = proxy_data[proxy_id]['proxy_prompt']
                self.ssh = paramiko.SSHClient()
                self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.ssh.connect( self.ssh_proxy,
                                  username = proxy_data[proxy_id]['proxy_usr'], 
                                  password = proxy_data[proxy_id]['proxy_pwd'])
                self.chan = self.ssh.invoke_shell()
                self.chan.settimeout(20)
        else:
            print("Fatal error wrong key " + proxy_id)
            exit(0)
    
    def writeLog(self, log_text):
        if (self.LOG_FLAG):
            self.log_ptr.write(log_text)
    
    def setLogFlag (self):
        self.LOG_FLAG = 1
        self.log_ptr = open(self.log_dir + "LOG "+time.strftime("%Y_%m_%d")+"   "+time.strftime("%H_%M_%S")+".txt",'w')
    
    def node_login(self, ip, **kwargs):
        if 'router' in kwargs:
            router = kwargs['router']
        else:
            router = None
        buffer = ''
        if self.ssh == None:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect( ip, self.rou_user, self.rou_pwd)
            self.chan = self.ssh.invoke_shell()
            self.chan.settimeout(20)
            self.chan.send('\n')
            while not re.search('\r\n.*#',buffer):
                resp = self.chan.recv(ssh_manager.CHANNEL_LENGTH)
                buffer += resp.decode()
        else:
            if not self.prompt == self.proxy_prompt:
                self.node_logout()
            try:
                self.chan.send('ssh -l '+self.rou_user+' '+ip+'\n')
                buffer = ''
                while not re.search(self.pwd_prompt, buffer):
                    resp = self.chan.recv(ssh_manager.CHANNEL_LENGTH)
                    buffer += resp.decode()
                    # server requests it in case the key is new
                    if re.search("\(yes\/no\)\?\s+", buffer):
                        buffer = ''
                        self.chan.send("yes\n")
                        #print (" new ssh key ")
            except:
                print("Router with ip '"+ip+"' DEAD or not responding\n")
                self.prompt = self.proxy_prompt
                self.run_cmd('\x03')
                return 0
            self.chan.send(self.rou_pwd+'\n')
            while not re.search('\r\n.*#',buffer):
                resp = self.chan.recv(ssh_manager.CHANNEL_LENGTH)
                buffer += resp.decode()
                print(buffer)

        # we retrieve the router's name, prompt, config prompt
        self.prompt = re.search('(\r\n.*#)',buffer).group(1)
        self.router_prompt = self.prompt
        self.router_name = re.search('\r\n(.*)#',buffer).group(1)
        # in case the hostname is too long, when you go in 'conf t' mode,
        # the hostname is cut to the first 22 characters
        if len(self.prompt)>23:
            self.config_prompt = self.prompt[:22]+"\(config.*\)#"
        else:
            self.config_prompt = re.search('(\r\n.*)#',buffer).group(1)+"\(config.*\)#"
        
        if (router and re.search('\r\n(.*)#',buffer).group(1).strip()!=router):
            print(", NAME ERROR for router "+router+" hostname "+self.prompt)
        self.writeLog("\nConnected to '"+self.router_name+"' ...\n\n"+self.router_name+"#")
        self.chan.settimeout(30)
        return 1
    
    # exiting from the router/switch
    def node_logout(self):
        self.exit_conf_t()
        if self.ssh_proxy == None:
            self.ssh.exec_command("exit")
            self.ssh.close()
        elif not self.prompt == self.proxy_prompt:
            self.prompt = self.proxy_prompt
            self.run_cmd("exit")

    def run_cmd(self, cmd, newline='\n'):
        self.chan.send(cmd + newline)
        buffer = ''
        while not re.search(self.prompt, buffer):
            resp = self.chan.recv(ssh_manager.CHANNEL_LENGTH)
            buffer += resp.decode()
            if re.search("\r\n --More-- ", buffer):
                self.chan.send(' ')
            #print("BUFFER:",buffer)
        #self.writeLog(buffer.replace("\r\n", "\n"))
        return buffer.replace("\r\n","\n")
    
    # enter the Cisco "configure terminal" mode ... this functions sets the new prompt
    # and also considers that the prompt is "cut" in case the hostname is too long.
    def conf_t(self):
        self.prompt = self.config_prompt
        buffer = self.run_cmd('configure terminal\n')
        self.writeLog(buffer.replace("\r\n", "\n"))
    
    # exit from 'configure terminal' mode
    def exit_conf_t(self):
        if (re.search("\(config.*\)#", self.prompt)):
            self.prompt = self.router_prompt
            buffer = self.run_cmd('end\n')
            self.writeLog(buffer.replace("\r\n", "\n"))

    # exit from the proxy ssh server and close the connection
    def close(self):
        self.exit_conf_t()
        self.node_logout()
        if self.ssh_proxy != None:
            self.ssh.exec_command("exit")
            self.ssh.close()


# this class telnets directly to the devices, there is no proxy or any other
# bridge machine in between, so we remove everything related to it
# the target ip address needs to be passed as an argument during the object
# creation, such as the router's name, which is checked against the hostname
# configured on the device (it doesn't need to be necessarily correct).
telnet_data = {  'telnet_with_proxy'  : {  "telnet_proxy" : "",
                            "proxy_prompt" : "",
                            "proxy_usr" : "",
                            "proxy_pwd" : "",
                            "rou_user" : "",
                            "rou_pwd" : "",
                            "log_dir" : ""    
                            },
                # no proxy in this case
                'telnet_no_proxy'  : { 
                                "rou_user" : "",
                                "rou_pwd" : "",
                                "log_dir" : ""    
                              }
              }

class telnet_manager ():
    # we save hereafter the prompts as encoded binary vectors, to be used in telnet expect function
    # this is quite helpful, since they can be used to easily manage access to many different
    # device types, for example IOS routers and Nexus switches, or Linux servers. If you don't
    # directly enter in enable mode, it can be checked to solve also this issue.
    login_prompt = [("login: ").encode(), ("username: ").encode(), ("Username: ").encode()]
    pwd_prompt = [("Password: ").encode(), ("password: ").encode()]
    cisco_prompt = [("\r\n.*#").encode(), ("\r\n.*>").encode()]
    
    # during instantiation of an object of this class, if there is a proxy we
    # already connect to it, otherwise we connect through the function node_login
    def __init__(self, proxy_id):
        self.router_name = ''
        self.router_prompt = ''
        self.config_prompt = ['']
        self.telnet_proxy = None
        self.tn = None
        self.LOG_FLAG = 0
        
        # should be tested if read_until or expect work in the same way ...
        # expect seems to be more powerful
        if proxy_id in telnet_data:
            if 'telnet_proxy' in telnet_data[proxy_id]:
                self.telnet_proxy = telnet_data[proxy_id]['telnet_proxy']
                self.tn = telnetlib.Telnet(self.telnet_proxy)
                # set to 1 to see the telnet's output
                self.tn.set_debuglevel(0)
                self.tn.expect(telnet_manager.login_prompt, 10)
                self.tn.write(telnet_data[proxy_id]['proxy_usr'].encode())
                self.tn.expect(telnet_manager.pwd_prompt, 10)
                self.tn.write(telnet_data[proxy_id]['proxy_pwd'].encode())
                self.tn.read_until(telnet_data[proxy_id]['proxy_prompt'].encode())
            self.rou_user = telnet_data[proxy_id]['rou_user']
            self.rou_pwd = telnet_data[proxy_id]['rou_pwd']
    
    def writeLog(self, log_text):
        if (self.LOG_FLAG):
            self.log_ptr.write(log_text)
    
    def setLogFlag (self):
        self.LOG_FLAG = 1
        self.log_ptr = open(self.log_dir + "LOG "+time.strftime("%Y_%m_%d")+"   "+time.strftime("%H_%M_%S")+".txt",'w')
    
    # we need to distinguish between the proxy case and the case in which we
    # directly telnet to the target router/device. The router's name is an optional parameter,
    # if it is known it can be passed and it is checked against the router's hostname.
    def node_login (self, ip, **kwargs):
        if not self.telnet_proxy == None:
            self.tn.write(("telnet "+ ip +"\n").encode())
        else:
            self.tn = telnetlib.Telnet(ip)
            self.tn.set_debuglevel(0)
        if 'router' in kwargs:
            router = kwargs['router']
        else:
            router = None
        self.tn.expect(telnet_manager.login_prompt, 10)
        self.tn.write(self.rou_user.encode())
        self.tn.expect(telnet_manager.pwd_prompt)
        self.tn.write(self.rou_pwd.encode())
        [index,obj,output] = self.tn.expect(self.cisco_prompt, 10)
        dec_out = output.decode()
        # checking if we are entering enable mode, in this case we send "enable" and repeat the password
        if (re.search("\r\n.*>",dec_out)):
            self.prompt = [("\r\n"+re.search("\r\n(.*)>",dec_out).group(1)+"#").encode()]
            self.router_name = re.search("\r\n(.*)>",dec_out).group(1).strip()
            self.tn.write("enable\n".encode())
            self.tn.expect(telnet_manager.pwd_prompt, 10)
            self.tn.write(self.rou_pwd.encode())
            self.tn.expect(self.prompt, 10)
        elif (re.search("\r\nLogin incorrect#",dec_out)):
            return None
        elif (re.search("\r\n.*#", dec_out)):
            self.prompt = [(re.search("(\r\n.*#)",dec_out).group(1)).encode()]
            self.router_name = re.search("\r\n(.*)#",dec_out).group(1).strip()
        else:
            print("ERROR in logging in, could not find expected prompt, last output:\n" + output.decode())
            self.tn.write('\x03'.encode())
            return None
        
        if len(self.prompt[0].decode())>23:
            self.config_prompt = [(self.prompt[0].decode()[:22]+"\(config.*\)#").encode()]
        else:
            self.config_prompt = [("\r\n"+self.router_name+"\(config.*\)#").encode()]
        
        # this is important to speed up things and avoid problems with the usage of the expect
        # function when running commands.
        self.run_cmd('terminal length 0')
        self.writeLog("\nConnected to '"+self.router_name+"' ...\n\n"+self.router_name+"#")
        
        if (router and self.router_name != router):
            print(" NAME ERROR for ip " + ip + " real name: "+self.router_name+" passed name: "+router)
    
    def node_logout (self):
        self.exit_conf_t()
        if self.telnet_proxy == None:
            self.tn.write("exit\n".encode())
            self.tn.close()
        elif not self.prompt == self.proxy_prompt:
            self.prompt = self.proxy_prompt
            self.run_cmd("exit")
    
    def run_cmd (self,cmd):
        try:
            self.tn.write((cmd+'\n').encode())
            [index,obj,output] = self.tn.expect(self.prompt, timeout=30)
        except:
            print ("timed out command: "+cmd+", gathered output:\n"+output.decode())
        text_out = output.decode().replace("\r\n","\n")
        self.writeLog(text_out)
        return text_out
    
    def conf_t (self):
        self.prompt = self.config_prompt
        self.run_cmd('configure terminal\n')

    def exit_conf_t (self):
        if (re.search("\(config.*\)#",self.prompt[0].decode())):
            self.prompt = self.router_prompt
            self.run_cmd('end\n')
    
    def close (self):
        self.exit_conf_t()
        self.tn.write("exit\n".encode())
        self.tn.close()

