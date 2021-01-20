'''
@author    :  哈库呐玛塔塔
@date      :  2021-01-20
@describe  :  适用于深圳信息职业技术学院的今日校园自动签到脚本
'''

import os
import uuid
import base64
import re
import json
from datetime import datetime

import yaml
from logzero import logger
import requests
import yagmail
import pyDes
from Crypto.Cipher import AES
from pytz import timezone


class Cpdaily:
    def __init__(self) -> None:
        # 今日校园App密钥
        self.key = 'b3L26XNL'
        # 登录url
        self.login_url = 'https://auth.sziit.edu.cn/authserver'
        # 登录成功后跳转的url
        self.login_success_url = 'https://auth.sziit.edu.cn/authserver/index.do'
        self.host = 'sziit.campusphere.net'
        self.session = requests.session()
        self.extension = {
            'lon': 0.0,
            'lat': 0.0,
            'model': 'Redmi K30 Pro',
            'appVersion': '8.1.14',
            'deviceId': str(uuid.uuid1()),
            'systemName': 'Android',
            'systemVersion': '4.4.4',
            'userId': 'foo'
        }
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36 Edg/83.0.478.37',
            'Pragma': 'no-cache',
            'Accept': 'application/json, text/plain, */*',
        }

    def desEncrypt(self, text: str) -> str:
        ''' des加密 '''
        k = pyDes.des(
            self.key, 
            pyDes.CBC, 
            b"\x01\x02\x03\x04\x05\x06\x07\x08",
            pad=None, 
            padmode=pyDes.PAD_PKCS5)
        ret = k.encrypt(text)
        return base64.b64encode(ret).decode()

    @staticmethod
    def pad(s: str, key: str) -> str:
        return s + (len(key) - len(s) % len(key)) * chr(len(key) - len(s) % len(key))
    
    def aesEncrypt(self, key: str, text: str) -> str:
        ''' aes加密 '''
        text = self.pad('TdEEGazAXQMBzEAisrYaxRRax5kmnMJnpbKxcE6jxQfWRwP2J78adKYm8WzSkfXJ' + text, key).encode('utf-8')
        aes = AES.new(str.encode(key), AES.MODE_CBC, str.encode('ya8C45aRrBEn8sZH'))
        return base64.b64encode(aes.encrypt(text))

    def login(self, username: str, password: str) -> bool:
        ''' 登录 '''
        ret = self.session.get(self.login_url)
        body = dict(re.findall(r'<input type="hidden" name="(.*?)" value="(.*?)"', ret.text))
        salt = dict(re.findall(r'<input type="hidden" id="(.*?)" value="(.*?)"', ret.text))
        if 'pwdDefaultEncryptSalt' in salt.keys():
            password = self.aesEncrypt(salt['pwdDefaultEncryptSalt'], password)

        body.update({
            'username': username,
            'password': password,
            'dllt': 'userNamePasswordLogin'
        })
        self.session.headers.update({
            **self.headers,
            'Referer': self.login_url,
            'Cpdaily-Extension': self.desEncrypt(json.dumps(self.extension))
        })
        ret = self.session.post(ret.url, data=body)
        logined = ret.url == self.login_success_url
        if not logined:
            logger.error('登录失败')
        return logined

    def getTaskList(self) -> list:
        ''' 获取所有未签到的任务 '''
        self.headers = {
            'Accept': 'application/json, text/plain, */*',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
            'content-type': 'application/json',
            'Accept-Encoding': 'gzip,deflate',
            'Accept-Language': 'zh-CN,en-US;q=0.8',
            'Content-Type': 'application/json;charset=UTF-8'
        }
        self.session.headers.update({
            **self.headers
        })
        # 第一次请求获取MOD_AUTH_CAS
        self.session.post(f'https://{self.host}/wec-counselor-sign-apps/stu/sign/getStuSignInfosInOneDay', data=json.dumps({}))
        # 第二次请求获取任务列表
        ret = self.session.post(f'https://{self.host}/wec-counselor-sign-apps/stu/sign/getStuSignInfosInOneDay', data=json.dumps({}))
        unsigned_tasks = ret.json()['datas']['unSignedTasks']
        if len(unsigned_tasks) < 1:
            logger.info('当前没有未签到的任务')
        return unsigned_tasks

    def getTaskDetail(self, wid: str, instance_id: str) -> dict:
        ''' 获取任务详情 '''
        body = {
            'signInstanceWid': instance_id,
            'signWid': wid
        }
        ret = self.session.post(f'https://{self.host}/wec-counselor-sign-apps/stu/sign/detailSignInstance', data=json.dumps(body))
        return ret.json()['datas']

    def fillForm(self, task: dict, fields: list, user: dict) -> dict:
        ''' 构造表单 '''
        extraFields = task['extraField']
        extraFieldItems = []
        for i, extraField in enumerate(extraFields):
            field = fields[i]
            for item in extraField['extraFieldItems']:
                if item['content'] == field['value']:
                    extraFieldItemValue = {
                        'extraFieldItemValue': field['value'],
                        'extraFieldItemWid': item['wid']
                    }
                    extraFieldItems.append(extraFieldItemValue)
        return {
            'signInstanceWid': task['signInstanceWid'],
            'longitude': user['lon'],
            'latitude': user['lat'],
            'isMalposition': task['isMalposition'],
            'position': user['address'],
            'extraFieldItems': extraFieldItems,
            'uaIsCpadaily': True
        }

    def submit(self, form: dict, user: dict) -> str:
        ''' 提交表单 '''
        self.extension['lat'] = user['lat']
        self.extension['lon'] = user['lon']
        self.extension['userId'] = user['username']
        self.session.headers.update({
            'CpdailyStandAlone': '0',
            'extension': '1',
            'Cpdaily-Extension': self.desEncrypt(json.dumps(self.extension)),
            'Connection': 'Keep-Alive'
        })
        ret = self.session.post(
            f'https://{self.host}/wec-counselor-sign-apps/stu/sign/submitSign', 
            data=json.dumps(form)).json()
        
        signed = ret['code'] == 0
        message = '签到成功' if signed else f"签到失败，原因：{ret['message']}"
        logger.info(message)
        return signed, message


def loadConfig(filename: str='config.yml') -> dict:
    ''' 读取yaml配置 '''
    file_ext = os.path.splitext(filename)[-1]
    if file_ext != '.yml' and file_ext != '.yaml':
        logger.error('配置文件后缀不是.yml或.yaml',)
        return

    config: Any
    with open(filename, 'r') as f:
        config = yaml.load(f.read(), Loader=yaml.FullLoader)
    return config


def sendByServerChan(sckey: str, subject: str, message: str) -> None:
    ''' 微信推送消息 '''
    if not sckey:
        logger.warn('serverChan的sckey为空')
        return
    
    subject = subject or message
    url = f'https://sc.ftqq.com/{sckey}.send'
    params = {
        'text': subject,
        'desp': message
    }
    ret = requests.get(url, params).json()
    
    if ret['errno'] != 0:
        logger.error(ret['errmsg'])
    else:
        logger.info('消息推送成功！')


def sendByEmail(
    user: str, 
    password: str, 
    host: str,
    to: str,
    subject: str,
    message: str
    ) -> None:
    ''' 发送邮件通知 '''
    yag = yagmail.SMTP(user=user, password=password, host=host)
    yag.send(to, subject, message)
    logger.info('发送邮件成功！')
    

def main():
    config = loadConfig('config.yml')
    users = config.get('users')
    fields = config.get('fields')
    email = config.get('email')
    cpdaily = Cpdaily()

    for user in users:
        print(user['username'])
        if cpdaily.login(user['username'], user['password']):
            task_list = cpdaily.getTaskList()
            for t in task_list:
                task = cpdaily.getTaskDetail(t['signWid'], t['signInstanceWid'])
                form = cpdaily.fillForm(task, fields, user)
                signed, message = cpdaily.submit(form, user)

                # 签到成功，推送消息
                if signed:
                    sendByServerChan(
                        sckey=user['sckey'], 
                        subject=user['serverChanSubject'], 
                        message=message)

                    now = datetime.now(timezone('Asia/Shanghai')).strftime('%Y年%m月%d日')
                    message = f'{now}\n{message}'
                    sendByEmail(
                        user=email['user'], 
                        password=email['password'], 
                        host=email['host'], 
                        to=user['email'],
                        subject=user['emailSubject'],
                        message=message
                    )


if __name__ == "__main__":
    main()
                    
