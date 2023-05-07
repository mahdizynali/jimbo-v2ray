with open ('uid_2053.txt', 'r') as u:
    '''open uid file which can be recive from x-ui panel'''
    
    u_id_2053 = [str(line.strip()) for line in u.readlines()]
    u.close()

with open ('uid_8443.txt', 'r') as u:
    '''open uid file which can be recive from x-ui panel'''
    
    u_id_8443 = [str(line.strip()) for line in u.readlines()]
    u.close()

with open ('good_ip.txt', 'r') as g :
    '''open cdn file ip which can be recive cloudflare ip'''
    
    g_ip = [str(line.strip()) for line in g.readlines()]
    g.close()

#===========================================================
payload1 = {
    "port" : "2053",
    "sni" : "www.bmisupport.site",
    "security" : "tls",
    "type" : "ws",
    "path" : "/less",
    "host" : "www.bmisupport.site",
    "config_name" : "fast_vless"
}
payload2 = {
    "port" : "8443",
    "sni" : "www.bmisupport.site",
    "security" : "tls",
    "type" : "ws",
    "path" : "/master",
    "host" : "www.bmisupport.site",
    "config_name" : "private_vless"
}
#===========================================================
def config_generator_2053 ():
    '''auto generating v2ray vless configs'''
    
    list_configs = []
    for i in range (len(u_id_2053)):
        config = {
            "vless://" + u_id_2053[i] + "@" + g_ip[i] + ":" + payload1["port"] + 
            "?sni=" + payload1["sni"] + 
            "&security=" + payload1["security"] +
            "&type=" + payload1["type"] +
            "&path=" + payload1["path"] +
            "&host=" + payload1["host"] +
            "#" + payload1["config_name"] + str(i + 1)
        }
        list_configs.append(config.pop()) 
        
    return list_configs

configs_fast = config_generator_2053()
#===========================================================
def config_generator_8443 ():
    '''auto generating v2ray vless configs'''
    
    list_configs = []
    for i in range (len(u_id_8443)):
        config = {
            "vless://" + u_id_8443[i] + "@" + g_ip[i] + ":" + payload2["port"] + 
            "?sni=" + payload2["sni"] + 
            "&security=" + payload2["security"] +
            "&type=" + payload2["type"] +
            "&path=" + payload2["path"] +
            "&host=" + payload2["host"] +
            "#" + payload2["config_name"] + str(i + 1)
        }
        list_configs.append(config.pop()) 
        
    return list_configs

configs_private = config_generator_8443()    
#===========================================================

with open ('vless_configs.txt', 'w') as vc :
    '''save configs into a text file'''
    
    for i in range(len(configs_private)):
        vc.write("\n" + configs_fast[i] + "\n\n")
    vc.write("="*50)
    
    for i in range(len(configs_fast)):
        vc.write("\n" + configs_fast[i] + "\n\n")
    vc.write("="*50)
    
    vc.close()
